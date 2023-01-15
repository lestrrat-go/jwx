package jose

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/lestrrat-go/jwx/v2/internal/jwxtest"
)

var executablePath string
var muExecutablePath sync.RWMutex

func init() {
	findExecutable()
}

func SetExecutable(path string) {
	muExecutablePath.Lock()
	defer muExecutablePath.Unlock()
	executablePath = path
}

func findExecutable() {
	p, err := exec.LookPath("jose")
	if err == nil {
		SetExecutable(p)
	}
}

func ExecutablePath() string {
	muExecutablePath.RLock()
	defer muExecutablePath.RUnlock()

	return executablePath
}

func Available() bool {
	muExecutablePath.RLock()
	defer muExecutablePath.RUnlock()

	return executablePath != ""
}

func RunJoseCommand(ctx context.Context, t *testing.T, args []string, outw, errw io.Writer) error {
	var errout bytes.Buffer
	var capout bytes.Buffer

	cmd := exec.CommandContext(ctx, ExecutablePath(), args...)
	if outw == nil {
		cmd.Stdout = &capout
	} else {
		cmd.Stdout = io.MultiWriter(outw, &capout)
	}

	if errw == nil {
		cmd.Stderr = &errout
	} else {
		cmd.Stderr = io.MultiWriter(outw, &errout)
	}

	t.Logf("Executing `%s %s`\n", ExecutablePath(), strings.Join(args, " "))
	if err := cmd.Run(); err != nil {
		t.Logf(`failed to execute command: %s`, err)

		if capout.Len() > 0 {
			t.Logf("captured output: %s", capout.String())
		}

		if errout.Len() > 0 {
			t.Logf("captured error: %s", errout.String())
		}

		return fmt.Errorf(`failed to execute command: %w`, err)
	}

	return nil
}

type AlgorithmSet struct {
	data map[string]struct{}
}

func NewAlgorithmSet() *AlgorithmSet {
	return &AlgorithmSet{
		data: make(map[string]struct{}),
	}
}

func (set *AlgorithmSet) Add(s string) {
	set.data[s] = struct{}{}
}

func (set *AlgorithmSet) Has(s string) bool {
	_, ok := set.data[s]
	return ok
}

func Algorithms(ctx context.Context, t *testing.T) (*AlgorithmSet, error) {
	var buf bytes.Buffer
	if err := RunJoseCommand(ctx, t, []string{"alg"}, &buf, nil); err != nil {
		return nil, fmt.Errorf(`failed to generate jose tool's supported algorithms: %w`, err)
	}

	set := NewAlgorithmSet()

	scanner := bufio.NewScanner(&buf)
	for scanner.Scan() {
		alg := scanner.Text()
		set.Add(alg)
	}
	return set, nil
}

// GenerateJwk creates a new key using the jose tool, and returns its filename and
// a cleanup function.
// The caller is responsible for calling the cleanup
// function and make sure all resources are released
func GenerateJwk(ctx context.Context, t *testing.T, template string) (string, func(), error) {
	t.Helper()

	file, cleanup, err := jwxtest.CreateTempFile("jwx-jose-key-*.jwk")
	if err != nil {
		return "", nil, fmt.Errorf(`failed to create temporary file: %w`, err)
	}

	if err := RunJoseCommand(ctx, t, []string{"jwk", "gen", "-i", template, "-o", file.Name()}, nil, nil); err != nil {
		return "", nil, fmt.Errorf(`failed to generate key: %w`, err)
	}

	return file.Name(), cleanup, nil
}

// EncryptJwe creates an encrypted JWE message and returns its filename and
// a cleanup function.
// The caller is responsible for calling the cleanup
// function and make sure all resources are released
func EncryptJwe(ctx context.Context, t *testing.T, payload []byte, alg string, keyfile string, enc string, compact bool) (string, func(), error) {
	t.Helper()

	var arg string
	if alg == "dir" {
		arg = fmt.Sprintf(`{"protected":{"alg":"dir","enc":"%s"}}`, enc)
	} else {
		arg = fmt.Sprintf(`{"protected":{"enc":"%s"}}`, enc)
	}

	cmdargs := []string{"jwe", "enc", "-k", keyfile, "-i", arg}
	if compact {
		cmdargs = append(cmdargs, "-c")
	}

	var pfile string
	if len(payload) > 0 {
		fn, pcleanup, perr := jwxtest.WriteFile("jwx-jose-payload-*", bytes.NewReader(payload))
		if perr != nil {
			return "", nil, fmt.Errorf(`failed to write payload to file: %w`, perr)
		}

		cmdargs = append(cmdargs, "-I", fn)
		pfile = fn
		defer pcleanup()
	}

	ofile, ocleanup, oerr := jwxtest.CreateTempFile(`jwx-jose-key-*.jwe`)
	if oerr != nil {
		return "", nil, fmt.Errorf(`failed to create temporary file: %w`, oerr)
	}

	cmdargs = append(cmdargs, "-o", ofile.Name())

	if err := RunJoseCommand(ctx, t, cmdargs, nil, nil); err != nil {
		defer ocleanup()
		if pfile != "" {
			jwxtest.DumpFile(t, pfile)
		}
		jwxtest.DumpFile(t, keyfile)
		return "", nil, fmt.Errorf(`failed to encrypt message: %w`, err)
	}

	return ofile.Name(), ocleanup, nil
}

func DecryptJwe(ctx context.Context, t *testing.T, cfile, kfile string) ([]byte, error) {
	t.Helper()

	cmdargs := []string{"jwe", "dec", "-i", cfile, "-k", kfile}
	var output bytes.Buffer
	if err := RunJoseCommand(ctx, t, cmdargs, &output, nil); err != nil {
		jwxtest.DumpFile(t, cfile)
		jwxtest.DumpFile(t, kfile)

		return nil, fmt.Errorf(`failed to decrypt message: %w`, err)
	}

	return output.Bytes(), nil
}

func FmtJwe(ctx context.Context, t *testing.T, data []byte) ([]byte, error) {
	t.Helper()

	fn, pcleanup, perr := jwxtest.WriteFile("jwx-jose-fmt-data-*", bytes.NewReader(data))
	if perr != nil {
		return nil, fmt.Errorf(`failed to write data to file: %w`, perr)
	}
	defer pcleanup()

	cmdargs := []string{"jwe", "fmt", "-i", fn}

	var output bytes.Buffer
	if err := RunJoseCommand(ctx, t, cmdargs, &output, nil); err != nil {
		jwxtest.DumpFile(t, fn)

		return nil, fmt.Errorf(`failed to format JWE message: %w`, err)
	}

	return output.Bytes(), nil
}

// SignJws signs a message and returns its filename and
// a cleanup function.
// The caller is responsible for calling the cleanup
// function and make sure all resources are released
func SignJws(ctx context.Context, t *testing.T, payload []byte, keyfile string, compact bool) (string, func(), error) {
	t.Helper()

	cmdargs := []string{"jws", "sig", "-k", keyfile}
	if compact {
		cmdargs = append(cmdargs, "-c")
	}

	var pfile string
	if len(payload) > 0 {
		fn, pcleanup, perr := jwxtest.WriteFile("jwx-jose-payload-*", bytes.NewReader(payload))
		if perr != nil {
			return "", nil, fmt.Errorf(`failed to write payload to file: %w`, perr)
		}

		cmdargs = append(cmdargs, "-I", fn)
		pfile = fn
		defer pcleanup()
	}

	ofile, ocleanup, oerr := jwxtest.CreateTempFile(`jwx-jose-sig-*.jws`)
	if oerr != nil {
		return "", nil, fmt.Errorf(`failed to create temporary file: %w`, oerr)
	}

	cmdargs = append(cmdargs, "-o", ofile.Name())

	if err := RunJoseCommand(ctx, t, cmdargs, nil, nil); err != nil {
		defer ocleanup()
		if pfile != "" {
			jwxtest.DumpFile(t, pfile)
		}
		jwxtest.DumpFile(t, keyfile)
		return "", nil, fmt.Errorf(`failed to sign message: %w`, err)
	}

	return ofile.Name(), ocleanup, nil
}

func VerifyJws(ctx context.Context, t *testing.T, cfile, kfile string) ([]byte, error) {
	t.Helper()

	cmdargs := []string{"jws", "ver", "-i", cfile, "-k", kfile, "-O-"}
	var output bytes.Buffer
	if err := RunJoseCommand(ctx, t, cmdargs, &output, nil); err != nil {
		jwxtest.DumpFile(t, cfile)
		jwxtest.DumpFile(t, kfile)

		return nil, fmt.Errorf(`failed to decrypt message: %w`, err)
	}

	return output.Bytes(), nil
}
