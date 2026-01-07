package jwk_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"
)

func TestImportError(t *testing.T) {
	t.Run("errors.Is compatibility", func(t *testing.T) {
		// Test that ImportError can be identified with errors.Is
		key := []byte(`{"kty":"invalid"}`)
		_, err := jwk.Import(key)
		if err == nil {
			t.Skip("Need an actual import error for this test")
		}

		// This test verifies the pattern works if an import error occurs
		require.True(t, errors.Is(err, jwk.ImportError()), "errors.Is() not working with ImportError")
	})

	t.Run("format verbs", func(t *testing.T) {
		// Test error formatting with different verbs
		key := []byte(`{"kty":"invalid"}`)
		_, err := jwk.Import(key)
		if err == nil {
			t.Skip("Need an actual import error for this test")
		}

		concise := fmt.Sprintf("%s", err)
		verbose := fmt.Sprintf("%+v", err)

		// Concise should contain the operation context
		if !strings.Contains(concise, "jwk.Import") && !strings.Contains(concise, "import") {
			t.Errorf("concise format missing operation context: %s", concise)
		}

		// Verbose should be at least as detailed as concise
		if len(verbose) < len(concise) {
			t.Errorf("verbose format should be at least as long as concise")
		}
	})
}

func TestExportError(t *testing.T) {
	t.Run("errors.Is compatibility", func(t *testing.T) {
		// ExportError sentinel should be identifiable
		err := jwk.ExportError()
		require.NotNil(t, err, "ExportError() should return non-nil error")

		require.True(t, errors.Is(err, jwk.ExportError()), "errors.Is() not working with ExportError")
	})

	t.Run("Unwrap", func(t *testing.T) {
		// Verify ExportError can be unwrapped
		err := jwk.ExportError()
		unwrapped := errors.Unwrap(err)
		require.NotNil(t, unwrapped, "ExportError should be unwrappable")
	})
}

func TestParseError(t *testing.T) {
	t.Run("errors.Is compatibility", func(t *testing.T) {
		// Test that ParseError can be identified with errors.Is
		invalidJSON := []byte(`not valid json`)
		_, err := jwk.Parse(invalidJSON)
		require.Error(t, err, "expected parse error for invalid JSON")

		require.True(t, errors.Is(err, jwk.ParseError()), "errors.Is() not working with ParseError: %v", err)
	})

	t.Run("format verbs", func(t *testing.T) {
		// Test error formatting
		invalidJSON := []byte(`not valid json`)
		_, err := jwk.Parse(invalidJSON)
		require.Error(t, err, "expected parse error")

		concise := fmt.Sprintf("%s", err)
		verbose := fmt.Sprintf("%+v", err)

		// Concise should have operation context
		require.True(t,
			strings.Contains(concise, "jwk.Parse") || strings.Contains(concise, "parse"),
			"concise missing context: %s", concise)

		// Should have some root cause information
		require.GreaterOrEqual(t, len(concise), 10, "concise error too short: %s", concise)

		// Verbose should provide more detail
		require.GreaterOrEqual(t, len(verbose), len(concise), "verbose should be at least as detailed as concise")
	})

	t.Run("ParseReader variant", func(t *testing.T) {
		// Test ParseReader error variant
		invalidJSON := strings.NewReader(`not valid json`)
		_, err := jwk.ParseReader(invalidJSON)
		require.Error(t, err, "expected parse error")

		require.True(t, errors.Is(err, jwk.ParseError()), "ParseReader errors should be ParseError type")

		concise := fmt.Sprintf("%s", err)
		// Should mention ParseReader in context
		require.True(t,
			strings.Contains(concise, "ParseReader") || strings.Contains(concise, "parse"),
			"ParseReader error missing context: %s", concise)
	})

	t.Run("ParseString variant", func(t *testing.T) {
		// Test ParseString error variant
		invalidJSON := `not valid json`
		_, err := jwk.ParseString(invalidJSON)
		require.Error(t, err, "expected parse error")

		require.True(t, errors.Is(err, jwk.ParseError()), "ParseString errors should be ParseError type")

		concise := fmt.Sprintf("%s", err)
		// Should mention ParseString in context
		require.True(t,
			strings.Contains(concise, "ParseString") || strings.Contains(concise, "parse"),
			"ParseString error missing context: %s", concise)
	})
}

func TestErrorFormatVerbs(t *testing.T) {
	testCases := []struct {
		name      string
		operation func() error
	}{
		{
			name: "ParseError",
			operation: func() error {
				_, err := jwk.Parse([]byte(`invalid`))
				return err
			},
		},
		{
			name: "ParseReaderError",
			operation: func() error {
				_, err := jwk.ParseReader(strings.NewReader(`invalid`))
				return err
			},
		},
		{
			name: "ParseStringError",
			operation: func() error {
				_, err := jwk.ParseString(`invalid`)
				return err
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.operation()
			require.Error(t, err, "expected error")

			// Test different format verbs
			s := fmt.Sprintf("%s", err)
			v := fmt.Sprintf("%v", err)
			plusV := fmt.Sprintf("%+v", err)
			q := fmt.Sprintf("%q", err)

			// %s and %v should be identical (concise mode)
			require.Equal(t, s, v, "%%s and %%v should be identical:\n  %%s: %s\n  %%v: %s", s, v)

			// %+v should be at least as long (verbose mode)
			require.GreaterOrEqual(t, len(plusV), len(s), "%%+v should be at least as long as %%s")

			// %q should be quoted version
			require.True(t, strings.HasPrefix(q, `"`), "%%q should be quoted: %s", q)
			require.True(t, strings.HasSuffix(q, `"`), "%%q should be quoted: %s", q)

			// All formats should have some content
			require.Greater(t, len(s), 0, "error message should not be empty")
			require.Greater(t, len(v), 0, "error message should not be empty")
			require.Greater(t, len(plusV), 0, "error message should not be empty")
		})
	}
}

func TestContinueError(t *testing.T) {
	t.Run("ContinueError is opaque sentinel", func(t *testing.T) {
		// ContinueError should return the same instance
		err1 := jwk.ContinueError()
		err2 := jwk.ContinueError()

		require.Equal(t, err1, err2, "ContinueError should return same instance")

		// Should have a message
		require.NotEmpty(t, err1.Error(), "ContinueError should have an error message")
	})
}
