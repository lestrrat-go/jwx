package jose

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/lestrrat-go/pdebug"
	"github.com/pkg/errors"
)

// Error is returned by LookPath when it fails to classify a file as an
// executable.
type Error struct {
	// Name is the file name for which the error occurred.
	Name string
	// Err is the underlying error.
	Err error
}

func (e *Error) Error() string {
	return "exec: " + strconv.Quote(e.Name) + ": " + e.Err.Error()
}

func (e *Error) Unwrap() error { return e.Err }

var ErrNotFound = errors.New("executable file not found in $PATH")


func gofindExecutable(file string) error {
	d, err := os.Stat(file)
	if err != nil {
		fmt.Printf("os.Stat %s failed: %s\n", file, err)
		return err
	}
	if m := d.Mode(); !m.IsDir() && m&0111 != 0 {
		return nil
	}
	return os.ErrPermission
}

func goLookPath(file string) (string, error) {
	// NOTE(rsc): I wish we could use the Plan 9 behavior here
	// (only bypass the path if file begins with / or ./ or ../)
	// but that would not match all the Unix shells.

	if strings.Contains(file, "/") {
		err := gofindExecutable(file)
		if err == nil {
			return file, nil
		}
		return "", &Error{file, err}
	}
	path := os.Getenv("PATH")
	for _, dir := range filepath.SplitList(path) {
		if dir == "" {
			// Unix shell semantics: path element "" means "."
			dir = "."
		}
		path := filepath.Join(dir, file)
		fmt.Printf("Checking %s\n", path)
		if err := gofindExecutable(path); err == nil {
			fmt.Printf("Found at %s\n", path)
			return path, nil
		}
	}
	fmt.Println("Tried all paths, no avail")
	return "", &Error{file, ErrNotFound}
}

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
	p, err := goLookPath("jose")
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

	return executablePath == ""
}

func createTempfile(t *testing.T, template string) (*os.File, func(), error) {
	t.Helper()

	file, err := ioutil.TempFile("", template)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to create temporary file")
	}

	//	t.Logf("Created file %s", file.Name())
	cleanup := func() {
		//		t.Logf("Closing and removing file %s", file.Name())
		file.Close()
		os.Remove(file.Name())
	}

	return file, cleanup, nil
}

// GenerateJwk creates a new key using the jose tool, and returns its filename and
// a cleanup function.
// The caller is responsible for calling the cleanup
// function and make sure all resources are released
func GenerateJwk(ctx context.Context, t *testing.T, template string) (string, func(), error) {
	t.Helper()

	file, cleanup, err := createTempfile(t, "jwx-jose-key-*.jwk")
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

	cmdargs := []string{ExecutablePath(), "jwe", "enc", "-k", keyfile}
	if len(payload) > 0 {
		pfile, pcleanup, perr := createTempfile(t, "jwx-jose-payload-*")
		if perr != nil {
			return "", nil, errors.Wrap(perr, `failed to create temporary file`)
		}
		//nolint:errcheck
		pfile.Write(payload)
		//nolint:errcheck
		pfile.Sync()

		cmdargs = append(cmdargs, "-I", pfile.Name())
		defer pcleanup()
	}

	ofile, ocleanup, oerr := createTempfile(t, `jwx-jose-key-*.jwe`)
	if oerr != nil {
		return "", nil, errors.Wrap(oerr, "failed to create temporary file")
	}

	cmdargs = append(cmdargs, "-o", ofile.Name())

	var errdst bytes.Buffer
	t.Logf("Executing `%s`\n", strings.Join(cmdargs, " "))
	cmd := exec.CommandContext(ctx, cmdargs[0], cmdargs[1:]...)
	cmd.Stderr = &errdst

	if err := cmd.Run(); err != nil {
		defer ocleanup()
		t.Logf("Error executing command: %s", errdst.String())

		return "", nil, errors.Wrap(err, `failed to encrypt message`)
	}

	return ofile.Name(), ocleanup, nil
}

func DecryptJwe(ctx context.Context, t *testing.T, cfile, kfile string) ([]byte, error) {
	t.Helper()

	cmdargs := []string{ExecutablePath(), "jwe", "dec", "-i", cfile, "-k", kfile}
	if pdebug.Enabled {
		cbuf, _ := ioutil.ReadFile(cfile)
		pdebug.Printf(`JWE message file contains "%s"`, cbuf)
		kbuf, _ := ioutil.ReadFile(kfile)
		pdebug.Printf(`JWK key file contains "%s"`, kbuf)
	}

	var errdst bytes.Buffer
	var output bytes.Buffer
	t.Logf("Executing `%s`\n", strings.Join(cmdargs, " "))
	cmd := exec.CommandContext(ctx, cmdargs[0], cmdargs[1:]...)
	cmd.Stderr = &errdst
	cmd.Stdout = &output

	if err := cmd.Run(); err != nil {
		t.Logf("Error executing command: %s", errdst.String())

		return nil, errors.Wrap(err, `failed to decrypt message`)
	}

	return output.Bytes(), nil
}
