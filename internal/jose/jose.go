package jose

import (
	"bytes"
	"context"
	"io"
	"io/ioutil"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/lestrrat-go/jwx/internal/jwxtest"
	"github.com/lestrrat-go/pdebug"
	"github.com/pkg/errors"
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

func RunJoseCommand(ctx context.Context, t *testing.T, args []string, out io.Writer) error {
	var errout bytes.Buffer
	var capout bytes.Buffer

	cmd := exec.CommandContext(ctx, ExecutablePath(), args...)
	cmd.Stderr = &errout
	if out == nil {
		cmd.Stdout = &capout
	} else {
		cmd.Stdout = io.MultiWriter(out, &capout)
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

		return errors.Wrap(err, `failed to execute command`)
	}

	return nil
}

// GenerateJwk creates a new key using the jose tool, and returns its filename and
// a cleanup function.
// The caller is responsible for calling the cleanup
// function and make sure all resources are released
func GenerateJwk(ctx context.Context, t *testing.T, template string) (string, func(), error) {
	t.Helper()

	file, cleanup, err := jwxtest.CreateTempFile("jwx-jose-key-*.jwk")
	if err != nil {
		return "", nil, errors.Wrap(err, "failed to create temporary file")
	}

	var errdst bytes.Buffer

	cmd := exec.CommandContext(ctx, ExecutablePath(), "jwk", "gen", "-i", template, "-o", file.Name())
	cmd.Stderr = &errdst

	if err := cmd.Run(); err != nil {
		defer cleanup()
		t.Logf(`failed to execute command: %s`, errdst.String())

		return "", nil, errors.Wrap(err, `failed to generate key`)
	}

	return file.Name(), cleanup, nil
}

// EncryptJwe creats an encrypted JWE message and returns its filename and
// a cleanup function.
// The caller is responsible for calling the cleanup
// function and make sure all resources are released
func EncryptJwe(ctx context.Context, t *testing.T, payload []byte, keyfile string) (string, func(), error) {
	t.Helper()

	cmdargs := []string{"jwe", "enc", "-k", keyfile}
	var pfile string
	if len(payload) > 0 {
		fn, pcleanup, perr := jwxtest.WriteFile("jwx-jose-payload-*", bytes.NewReader(payload))
		if perr != nil {
			return "", nil, errors.Wrap(perr, `failed to write payload to file`)
		}

		cmdargs = append(cmdargs, "-I", fn)
		pfile = fn
		defer pcleanup()
	}

	ofile, ocleanup, oerr := jwxtest.CreateTempFile(`jwx-jose-key-*.jwe`)
	if oerr != nil {
		return "", nil, errors.Wrap(oerr, "failed to create temporary file")
	}

	cmdargs = append(cmdargs, "-o", ofile.Name())

	if err := RunJoseCommand(ctx, t, cmdargs, nil); err != nil {
		defer ocleanup()
		if pfile != "" {
			jwxtest.DumpFile(t, pfile)
		}
		jwxtest.DumpFile(t, keyfile)
		return "", nil, errors.Wrap(err, `failed to encrypt message`)
	}

	return ofile.Name(), ocleanup, nil
}

func DecryptJwe(ctx context.Context, t *testing.T, cfile, kfile string) ([]byte, error) {
	t.Helper()

	cmdargs := []string{"jwe", "dec", "-i", cfile, "-k", kfile}
	if pdebug.Enabled {
		cbuf, _ := ioutil.ReadFile(cfile)
		pdebug.Printf(`JWE message file contains "%s"`, cbuf)
		kbuf, _ := ioutil.ReadFile(kfile)
		pdebug.Printf(`JWK key file contains "%s"`, kbuf)
	}

	var output bytes.Buffer
	if err := RunJoseCommand(ctx, t, cmdargs, &output); err != nil {
		jwxtest.DumpFile(t, cfile)
		jwxtest.DumpFile(t, kfile)

		return nil, errors.Wrap(err, `failed to decrypt message`)
	}

	return output.Bytes(), nil
}

func FmtJwe(ctx context.Context, t *testing.T, data []byte) ([]byte, error) {
	t.Helper()

	fn, pcleanup, perr := jwxtest.WriteFile("jwx-jose-fmt-data-*", bytes.NewReader(data))
	if perr != nil {
		return nil, errors.Wrap(perr, `failed to write data to file`)
	}
	defer pcleanup()

	cmdargs := []string{"jwe", "fmt", "-i", fn}

	var output bytes.Buffer
	if err := RunJoseCommand(ctx, t, cmdargs, &output); err != nil {
		jwxtest.DumpFile(t, fn)

		return nil, errors.Wrap(err, `failed to format JWE message`)
	}

	return output.Bytes(), nil
}
