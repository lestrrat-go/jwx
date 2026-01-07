package jwe_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/stretchr/testify/require"
)

func TestEncryptError(t *testing.T) {
	t.Run("errors.Is compatibility", func(t *testing.T) {
		// Test with actual encrypt error
		_, err := jwe.Encrypt([]byte("payload"))
		if err == nil {
			t.Skip("Need an actual encrypt error for this test")
		}

		require.True(t, errors.Is(err, jwe.EncryptError()), "errors.Is() not working with EncryptError: %v", err)
	})

	t.Run("format verbs", func(t *testing.T) {
		// Test with actual encrypt error
		_, err := jwe.Encrypt([]byte("payload"))
		if err == nil {
			t.Skip("Need an actual encrypt error for this test")
		}

		concise := fmt.Sprintf("%s", err)
		verbose := fmt.Sprintf("%+v", err)

		// Concise should have operation context
		require.True(t,
			strings.Contains(concise, "jwe.Encrypt") || strings.Contains(concise, "encrypt"),
			"concise missing context: %s", concise)

		// Verbose should be at least as detailed as concise
		require.GreaterOrEqual(t, len(verbose), len(concise), "verbose should be at least as detailed as concise")
	})
}

func TestDecryptError(t *testing.T) {
	t.Run("errors.Is compatibility", func(t *testing.T) {
		// Test with invalid JWE data
		invalidJWE := []byte("not a valid jwe")
		_, err := jwe.Decrypt(invalidJWE)
		require.Error(t, err, "expected decrypt error")

		require.True(t, errors.Is(err, jwe.DecryptError()), "errors.Is() not working with DecryptError: %v", err)
	})

	t.Run("format verbs", func(t *testing.T) {
		invalidJWE := []byte("not a valid jwe")
		_, err := jwe.Decrypt(invalidJWE)
		require.Error(t, err, "expected decrypt error")

		concise := fmt.Sprintf("%s", err)
		verbose := fmt.Sprintf("%+v", err)

		// Concise should have operation context
		require.True(t,
			strings.Contains(concise, "jwe.Decrypt") || strings.Contains(concise, "decrypt"),
			"concise missing context: %s", concise)

		// Should have some error detail
		require.GreaterOrEqual(t, len(concise), 10, "concise error too short: %s", concise)

		// Verbose should provide more detail
		require.GreaterOrEqual(t, len(verbose), len(concise), "verbose should be at least as detailed as concise")
	})
}

func TestParseError(t *testing.T) {
	t.Run("errors.Is compatibility", func(t *testing.T) {
		// Test with invalid JWE data
		invalidJWE := []byte("not valid jwe")
		_, err := jwe.Parse(invalidJWE)
		require.Error(t, err, "expected parse error")

		require.True(t, errors.Is(err, jwe.ParseError()), "errors.Is() not working with ParseError: %v", err)
	})

	t.Run("format verbs", func(t *testing.T) {
		invalidJWE := []byte("not valid jwe")
		_, err := jwe.Parse(invalidJWE)
		require.Error(t, err, "expected parse error")

		concise := fmt.Sprintf("%s", err)
		verbose := fmt.Sprintf("%+v", err)

		// Concise should have operation context
		require.True(t,
			strings.Contains(concise, "jwe.Parse") || strings.Contains(concise, "parse"),
			"concise missing context: %s", concise)

		// Should have some root cause information
		require.GreaterOrEqual(t, len(concise), 10, "concise error too short: %s", concise)

		// Verbose should provide more detail
		require.GreaterOrEqual(t, len(verbose), len(concise), "verbose should be at least as detailed as concise")
	})

	t.Run("ParseReader variant", func(t *testing.T) {
		invalidJWE := strings.NewReader("not valid jwe")
		_, err := jwe.ParseReader(invalidJWE)
		require.Error(t, err, "expected parse error")

		require.True(t, errors.Is(err, jwe.ParseError()), "ParseReader errors should be ParseError type")

		concise := fmt.Sprintf("%s", err)
		// Should mention ParseReader in context
		require.True(t,
			strings.Contains(concise, "ParseReader") || strings.Contains(concise, "parse"),
			"ParseReader error missing context: %s", concise)
	})

	t.Run("ParseString variant", func(t *testing.T) {
		invalidJWE := "not valid jwe"
		_, err := jwe.ParseString(invalidJWE)
		require.Error(t, err, "expected parse error")

		require.True(t, errors.Is(err, jwe.ParseError()), "ParseString errors should be ParseError type")

		concise := fmt.Sprintf("%s", err)
		// Should mention ParseString in context
		require.True(t,
			strings.Contains(concise, "ParseString") || strings.Contains(concise, "parse"),
			"ParseString error missing context: %s", concise)
	})

	t.Run("Empty buffer error", func(t *testing.T) {
		// Test empty buffer specifically
		_, err := jwe.Parse([]byte(""))
		require.Error(t, err, "expected parse error for empty buffer")

		require.True(t, errors.Is(err, jwe.ParseError()), "empty buffer error should be ParseError type")

		concise := fmt.Sprintf("%s", err)
		require.True(t,
			strings.Contains(concise, "empty") || strings.Contains(concise, "buffer"),
			"empty buffer error should mention issue: %s", concise)
	})
}

func TestRecipientError(t *testing.T) {
	t.Run("RecipientError sentinel", func(t *testing.T) {
		// RecipientError sentinel should be identifiable
		err := jwe.RecipientError()
		require.NotNil(t, err, "RecipientError() should return non-nil error")

		require.True(t, errors.Is(err, jwe.RecipientError()), "errors.Is() not working with RecipientError")
	})

	t.Run("Unwrap", func(t *testing.T) {
		// Verify RecipientError can be unwrapped
		err := jwe.RecipientError()
		unwrapped := errors.Unwrap(err)
		require.NotNil(t, unwrapped, "RecipientError should be unwrappable")
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
				_, err := jwe.Parse([]byte("invalid"))
				return err
			},
		},
		{
			name: "ParseReaderError",
			operation: func() error {
				_, err := jwe.ParseReader(strings.NewReader("invalid"))
				return err
			},
		},
		{
			name: "ParseStringError",
			operation: func() error {
				_, err := jwe.ParseString("invalid")
				return err
			},
		},
		{
			name: "DecryptError",
			operation: func() error {
				_, err := jwe.Decrypt([]byte("invalid"))
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
