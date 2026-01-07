package jws_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/stretchr/testify/require"
)

func TestSignError(t *testing.T) {
	t.Run("errors.Is compatibility", func(t *testing.T) {
		// SignError sentinel should be identifiable
		err := jws.SignError()
		require.NotNil(t, err, "SignError() should return non-nil error")

		require.True(t, errors.Is(err, jws.SignError()), "errors.Is() not working with SignError")
	})

	t.Run("Unwrap", func(t *testing.T) {
		// Verify SignError can be unwrapped
		err := jws.SignError()
		unwrapped := errors.Unwrap(err)
		require.NotNil(t, unwrapped, "SignError should be unwrappable")
	})
}

func TestVerifyError(t *testing.T) {
	t.Run("errors.Is compatibility", func(t *testing.T) {
		// VerifyError sentinel should be identifiable
		err := jws.VerifyError()
		require.NotNil(t, err, "VerifyError() should return non-nil error")

		require.True(t, errors.Is(err, jws.VerifyError()), "errors.Is() not working with VerifyError")
	})

	t.Run("Unwrap", func(t *testing.T) {
		// Verify VerifyError can be unwrapped
		err := jws.VerifyError()
		unwrapped := errors.Unwrap(err)
		require.NotNil(t, unwrapped, "VerifyError should be unwrappable")
	})

	t.Run("actual verification failure", func(t *testing.T) {
		// Create a valid signed message
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		payload := []byte("test payload")
		signed, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), key))
		require.NoError(t, err)

		// Try to verify with wrong key
		wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		_, err = jws.Verify(signed, jws.WithKey(jwa.ES256(), &wrongKey.PublicKey))
		require.Error(t, err, "expected verify error with wrong key")

		// Should be a VerifyError
		require.True(t, errors.Is(err, jws.VerifyError()), "expected VerifyError, got: %T", err)

		// Check error message format
		concise := fmt.Sprintf("%s", err)
		verbose := fmt.Sprintf("%+v", err)

		// Concise should have operation context
		require.True(t,
			strings.Contains(concise, "jws.Verify") || strings.Contains(concise, "verify") || strings.Contains(concise, "verification"),
			"concise missing context: %s", concise)

		// Verbose should be at least as detailed
		require.GreaterOrEqual(t, len(verbose), len(concise), "verbose should be at least as detailed as concise")
	})
}

func TestVerificationError(t *testing.T) {
	t.Run("errors.Is compatibility", func(t *testing.T) {
		// VerificationError sentinel should be identifiable
		err := jws.VerificationError()
		require.NotNil(t, err, "VerificationError() should return non-nil error")

		require.True(t, errors.Is(err, jws.VerificationError()), "errors.Is() not working with VerificationError")
	})

	t.Run("Unwrap", func(t *testing.T) {
		// Verify VerificationError can be unwrapped
		err := jws.VerificationError()
		unwrapped := errors.Unwrap(err)
		require.NotNil(t, unwrapped, "VerificationError should be unwrappable")
	})

	t.Run("signature verification failure contains VerificationError", func(t *testing.T) {
		// Create a valid signed message
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		payload := []byte("test payload")
		signed, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), key))
		require.NoError(t, err)

		// Try to verify with wrong key
		wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		_, err = jws.Verify(signed, jws.WithKey(jwa.ES256(), &wrongKey.PublicKey))
		require.Error(t, err, "expected verify error")

		// Should contain both VerifyError and VerificationError in chain
		require.True(t, errors.Is(err, jws.VerifyError()), "should be a VerifyError")

		require.True(t, errors.Is(err, jws.VerificationError()), "should contain VerificationError in chain")
	})
}

func TestParseError(t *testing.T) {
	t.Run("errors.Is compatibility", func(t *testing.T) {
		// Test that ParseError can be identified with errors.Is
		invalidJWS := []byte(`not a valid jws`)
		_, err := jws.Parse(invalidJWS)
		require.Error(t, err, "expected parse error for invalid JWS")

		require.True(t, errors.Is(err, jws.ParseError()), "errors.Is() not working with ParseError: %v", err)
	})

	t.Run("format verbs", func(t *testing.T) {
		// Test error formatting
		invalidJWS := []byte(`not valid jws`)
		_, err := jws.Parse(invalidJWS)
		require.Error(t, err, "expected parse error")

		concise := fmt.Sprintf("%s", err)
		verbose := fmt.Sprintf("%+v", err)

		// Concise should have operation context
		require.True(t,
			strings.Contains(concise, "jws.Parse") || strings.Contains(concise, "parse"),
			"concise missing context: %s", concise)

		// Should have some root cause information
		require.GreaterOrEqual(t, len(concise), 10, "concise error too short: %s", concise)

		// Verbose should provide more detail
		require.GreaterOrEqual(t, len(verbose), len(concise), "verbose should be at least as detailed as concise")
	})

	t.Run("ParseReader variant", func(t *testing.T) {
		// Test ParseReader error variant
		invalidJWS := strings.NewReader(`not valid jws`)
		_, err := jws.ParseReader(invalidJWS)
		require.Error(t, err, "expected parse error")

		require.True(t, errors.Is(err, jws.ParseError()), "ParseReader errors should be ParseError type")

		concise := fmt.Sprintf("%s", err)
		// Should mention ParseReader in context
		require.True(t,
			strings.Contains(concise, "ParseReader") || strings.Contains(concise, "parse"),
			"ParseReader error missing context: %s", concise)
	})

	t.Run("ParseString variant", func(t *testing.T) {
		// Test ParseString error variant
		invalidJWS := `not valid jws`
		_, err := jws.ParseString(invalidJWS)
		require.Error(t, err, "expected parse error")

		require.True(t, errors.Is(err, jws.ParseError()), "ParseString errors should be ParseError type")

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
				_, err := jws.Parse([]byte(`invalid`))
				return err
			},
		},
		{
			name: "ParseReaderError",
			operation: func() error {
				_, err := jws.ParseReader(strings.NewReader(`invalid`))
				return err
			},
		},
		{
			name: "ParseStringError",
			operation: func() error {
				_, err := jws.ParseString(`invalid`)
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
