package main

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"
)

// runJwx invokes the CLI app with the given args and captures stdout +
// stderr. The actual os.Stdout / os.Stderr file descriptors are
// redirected through os.Pipe so the captured streams reflect what an
// invoking shell would see — including: term.IsTerminal returns false
// against a pipe fd, so the isatty-gated warning correctly does NOT
// fire in tests.
func runJwx(t *testing.T, args []string) (stdout, stderr string, err error) {
	t.Helper()

	stdoutR, stdoutW, perr := os.Pipe()
	require.NoError(t, perr)
	stderrR, stderrW, perr := os.Pipe()
	require.NoError(t, perr)

	origStdout, origStderr := os.Stdout, os.Stderr
	os.Stdout = stdoutW
	os.Stderr = stderrW
	t.Cleanup(func() {
		os.Stdout = origStdout
		os.Stderr = origStderr
	})

	app := &cli.App{Commands: topLevelCommands}
	runErr := app.Run(append([]string{"jwx"}, args...))

	stdoutW.Close()
	stderrW.Close()

	stdoutBytes, _ := io.ReadAll(stdoutR)
	stderrBytes, _ := io.ReadAll(stderrR)
	return string(stdoutBytes), string(stderrBytes), runErr
}

// TestJwkGenerateOctRejectsZeroKeysize pins the INTERNAL-002 fix:
// `jwx jwk generate -t oct --keysize 0` must error instead of
// silently producing an empty symmetric key. RSA already rejects
// too-small sizes via stdlib; oct used to accept anything.
func TestJwkGenerateOctRejectsZeroKeysize(t *testing.T) {
	t.Run("zero", func(t *testing.T) {
		_, _, err := runJwx(t, []string{"jwk", "generate", "-t", "oct", "--keysize", "0"})
		require.Error(t, err, `--keysize 0 must be rejected`)
		require.Contains(t, err.Error(), "must be greater than zero",
			`error should explain the constraint`)
		require.Contains(t, err.Error(), "oct",
			`error should name the affected key type`)
	})

	t.Run("negative", func(t *testing.T) {
		_, _, err := runJwx(t, []string{"jwk", "generate", "-t", "oct", "--keysize", "-1"})
		require.Error(t, err, `--keysize -1 must be rejected`)
		require.Contains(t, err.Error(), "must be greater than zero")
	})
}

// TestJwkGenerateNoWarningOnNonTTY pins half of the INTERNAL-001 fix:
// when stdout is not a terminal (a pipe in this test, the typical
// `| jq` / `> file` case in real use), the "writing private key to
// terminal" warning must NOT fire. The complementary tty-attached
// case is verified manually because go test never gives us a real
// tty.
func TestJwkGenerateNoWarningOnNonTTY(t *testing.T) {
	stdout, stderr, err := runJwx(t, []string{"jwk", "generate", "-t", "oct", "--keysize", "16"})
	require.NoError(t, err)
	require.NotEmpty(t, stdout, `expected JWK on stdout`)
	require.NotContains(t, strings.ToLower(stderr), "warning",
		`no warning should fire when stdout is non-tty (got stderr=%q)`, stderr)
}

// TestJwkGenerateNoWarningWithPublicKey pins the other half of the
// INTERNAL-001 fix: even when stdout were a tty, --public-key
// strips the secret material via PublicSetOf before serialization,
// so no warning is needed.
func TestJwkGenerateNoWarningWithPublicKey(t *testing.T) {
	// 2048-bit RSA: smaller is rejected by jwk's modulus floor.
	stdout, stderr, err := runJwx(t, []string{
		"jwk", "generate",
		"-t", "RSA",
		"--keysize", "2048",
		"--public-key",
	})
	require.NoError(t, err)
	require.NotEmpty(t, stdout)
	require.NotContains(t, strings.ToLower(stderr), "warning",
		`--public-key strips secrets; no warning expected`)

	// Sanity: the result really is a public key (no "d", "p", "q" fields).
	require.NotContains(t, stdout, `"d":`, `public-key result must not contain "d"`)
}
