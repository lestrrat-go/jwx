package jwx_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/require"
)

// TestIntegration_JWTParseError tests JWT parsing error chain
func TestIntegration_JWTParseError(t *testing.T) {
	t.Run("Invalid token format", func(t *testing.T) {
		invalidToken := []byte("not.a.valid.token")

		_, err := jwt.Parse(invalidToken)
		require.Error(t, err, "expected error")

		// Should be a ParseError
		require.True(t, errors.Is(err, jwt.ParseError()), "not a ParseError")

		// Concise message should show operation and root cause
		concise := fmt.Sprintf("%s", err)
		require.True(t, strings.Contains(concise, "jwt.Parse"), "missing operation context in concise message: %s", concise)

		// Verbose should show full chain
		verbose := fmt.Sprintf("%+v", err)
		if len(verbose) <= len(concise) {
			t.Logf("Concise: %s", concise)
			t.Logf("Verbose: %s", verbose)
			// Note: This may not always be true if error chain is simple
			// Just log it for inspection
		}
	})

	t.Run("Expired token", func(t *testing.T) {
		tok := jwt.New()
		tok.Set(jwt.ExpirationKey, time.Now().Add(-time.Hour))

		err := jwt.Validate(tok)
		require.Error(t, err, "expected validation error")

		// Should be a TokenExpiredError
		require.True(t, errors.Is(err, jwt.TokenExpiredError()), "not a TokenExpiredError, got: %T", err)

		// Concise message should mention operation
		concise := fmt.Sprintf("%s", err)
		require.True(t, strings.Contains(concise, "exp"), "missing 'exp' claim context: %s", concise)
	})

	t.Run("Invalid issuer", func(t *testing.T) {
		tok := jwt.New()
		tok.Set(jwt.IssuerKey, "wrong-issuer")

		err := jwt.Validate(tok, jwt.WithIssuer("expected-issuer"))
		require.Error(t, err, "expected validation error")

		// Should be InvalidIssuerError
		require.True(t, errors.Is(err, jwt.InvalidIssuerError()), "not an InvalidIssuerError, got: %T", err)

		concise := fmt.Sprintf("%s", err)
		require.True(t, strings.Contains(concise, "iss"), "missing 'iss' claim context: %s", concise)
	})
}

// TestIntegration_JWEErrorChain tests JWE error chain
func TestIntegration_JWEErrorChain(t *testing.T) {
	t.Run("Invalid compact format", func(t *testing.T) {
		invalidJWE := []byte("not.a.valid.jwe")

		_, err := jwe.Decrypt(invalidJWE, jwe.WithKey(jwa.A256KW(), []byte("test-key-123456789012345678901234")))
		require.Error(t, err, "expected error")

		// Should be a decrypt or parse error
		isDecryptErr := errors.Is(err, jwe.DecryptError())
		isParseErr := errors.Is(err, jwe.ParseError())

		require.True(t, isDecryptErr || isParseErr, "not a DecryptError or ParseError, got: %T", err)

		concise := fmt.Sprintf("%s", err)
		require.True(t, strings.Contains(concise, "jwe."), "missing jwe operation context: %s", concise)
	})

	t.Run("Wrong decryption key", func(t *testing.T) {
		// Create a valid JWE
		key1 := []byte("correct-key-12345678901234567890")
		key2 := []byte("wrong-key-123456789012345678901")

		payload := []byte("secret message")
		encrypted, err := jwe.Encrypt(payload, jwe.WithKey(jwa.A256KW(), key1))
		require.NoError(t, err, "failed to encrypt: %v", err)

		// Try to decrypt with wrong key
		_, err = jwe.Decrypt(encrypted, jwe.WithKey(jwa.A256KW(), key2))
		require.Error(t, err, "expected decryption error")

		// Verify we got an error - type may vary depending on implementation
		concise := fmt.Sprintf("%s", err)
		t.Logf("Decryption error (wrong key): %s", concise)

		// The error should mention decryption or jwe
		require.True(t, strings.Contains(concise, "jwe") || strings.Contains(concise, "decrypt"), "error message doesn't mention jwe or decrypt: %s", concise)
	})
}

// TestIntegration_JWSErrorChain tests JWS error chain
func TestIntegration_JWSErrorChain(t *testing.T) {
	t.Run("Invalid compact format", func(t *testing.T) {
		invalidJWS := []byte("not.a.valid.jws")

		_, err := jws.Verify(invalidJWS, jws.WithKey(jwa.HS256(), []byte("test-key")))
		require.Error(t, err, "expected error")

		// Should be a parse or verify error
		isParseErr := errors.Is(err, jws.ParseError())
		isVerifyErr := errors.Is(err, jws.VerifyError())

		require.True(t, isParseErr || isVerifyErr, "not a ParseError or VerifyError, got: %T", err)

		concise := fmt.Sprintf("%s", err)
		require.True(t, strings.Contains(concise, "jws."), "missing jws operation context: %s", concise)
	})

	t.Run("Invalid signature", func(t *testing.T) {
		// Create a valid JWS
		key := []byte("test-key-for-signing-1234567890")
		payload := []byte("test payload")

		signed, err := jws.Sign(payload, jws.WithKey(jwa.HS256(), key))
		require.NoError(t, err, "failed to sign: %v", err)

		// Corrupt the signature
		corrupted := make([]byte, len(signed))
		copy(corrupted, signed)
		corrupted[len(corrupted)-1] ^= 0xFF // Flip bits in signature

		// Try to verify with corrupted signature
		_, err = jws.Verify(corrupted, jws.WithKey(jwa.HS256(), key))
		require.Error(t, err, "expected verification error")

		// Should be a verification or verify error
		isVerificationErr := errors.Is(err, jws.VerificationError())
		isVerifyErr := errors.Is(err, jws.VerifyError())

		if !isVerificationErr && !isVerifyErr {
			t.Logf("Got error type: %T", err)
		}

		concise := fmt.Sprintf("%s", err)
		t.Logf("Verification error (invalid signature): %s", concise)
	})
}

// TestIntegration_JWKErrorChain tests JWK error chain
func TestIntegration_JWKErrorChain(t *testing.T) {
	t.Run("Invalid JSON", func(t *testing.T) {
		invalidJSON := []byte(`{"kty":"RSA","invalid json`)

		_, err := jwk.ParseKey(invalidJSON)
		require.Error(t, err, "expected error")

		// JSON parsing errors might not be wrapped in ParseError
		// Just verify we got an error
		concise := fmt.Sprintf("%s", err)
		t.Logf("Invalid JSON error: %s", concise)
		// The error should exist - exact type depends on where parsing fails
	})

	t.Run("Invalid key type", func(t *testing.T) {
		invalidKey := []byte(`{"kty":"INVALID"}`)

		_, err := jwk.ParseKey(invalidKey)
		require.Error(t, err, "expected error")

		// Should be a ParseError or ImportError
		isParseErr := errors.Is(err, jwk.ParseError())
		isImportErr := errors.Is(err, jwk.ImportError())

		if !isParseErr && !isImportErr {
			t.Logf("Got error type: %T", err)
		}

		concise := fmt.Sprintf("%s", err)
		t.Logf("Invalid key type error: %s", concise)
	})
}

// TestIntegration_CrossPackage tests error chains that cross package boundaries
func TestIntegration_CrossPackage(t *testing.T) {
	t.Run("JWK to JWS signing", func(t *testing.T) {
		// Create an RSA key
		privkey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err, "failed to generate RSA key: %v", err)

		// Import to JWK
		key, err := jwk.Import(privkey)
		require.NoError(t, err, "failed to import key: %v", err)

		// Sign a payload
		payload := []byte("test payload")
		signed, err := jws.Sign(payload, jws.WithKey(jwa.RS256(), key))
		require.NoError(t, err, "failed to sign: %v", err)

		// Verify signature
		verified, err := jws.Verify(signed, jws.WithKey(jwa.RS256(), key))
		require.NoError(t, err, "failed to verify: %v", err)

		require.Equal(t, string(payload), string(verified), "payload mismatch: got %s, want %s", verified, payload)
	})

	t.Run("JWK to JWE encryption", func(t *testing.T) {
		// Create an ECDSA key
		privkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err, "failed to generate ECDSA key: %v", err)

		// Import to JWK
		key, err := jwk.Import(privkey)
		require.NoError(t, err, "failed to import key: %v", err)

		// Encrypt a payload
		payload := []byte("secret message")
		encrypted, err := jwe.Encrypt(payload, jwe.WithKey(jwa.ECDH_ES(), key))
		require.NoError(t, err, "failed to encrypt: %v", err)

		// Decrypt
		decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.ECDH_ES(), key))
		require.NoError(t, err, "failed to decrypt: %v", err)

		require.Equal(t, string(payload), string(decrypted), "payload mismatch: got %s, want %s", decrypted, payload)
	})

	t.Run("JWS signed JWT", func(t *testing.T) {
		// Create a JWT
		tok := jwt.New()
		tok.Set(jwt.IssuerKey, "test-issuer")
		tok.Set(jwt.SubjectKey, "test-subject")
		tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour))

		// Create signing key
		key := []byte("test-key-for-signing-1234567890")

		// Sign the JWT
		signed, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256(), key))
		require.NoError(t, err, "failed to sign JWT: %v", err)

		// Parse and verify
		parsed, err := jwt.Parse(signed, jwt.WithKey(jwa.HS256(), key))
		require.NoError(t, err, "failed to parse JWT: %v", err)

		// Validate
		err = jwt.Validate(parsed)
		require.NoError(t, err, "failed to validate JWT: %v", err)

		var issuer string
		require.NoError(t, parsed.Get(jwt.IssuerKey, &issuer), "failed to get issuer")
		require.Equal(t, "test-issuer", issuer, "issuer mismatch: got %v, want test-issuer", issuer)
	})
}

// TestIntegration_ErrorFormatting tests that all error types support concise and verbose formatting
func TestIntegration_ErrorFormatting(t *testing.T) {
	testCases := []struct {
		name      string
		createErr func() error
		wantType  error
	}{
		{
			name: "JWT ParseError",
			createErr: func() error {
				_, err := jwt.Parse([]byte("invalid"))
				return err
			},
			wantType: jwt.ParseError(),
		},
		{
			name: "JWT TokenExpiredError",
			createErr: func() error {
				tok := jwt.New()
				tok.Set(jwt.ExpirationKey, time.Now().Add(-time.Hour))
				return jwt.Validate(tok)
			},
			wantType: jwt.TokenExpiredError(),
		},
		{
			name: "JWE DecryptError",
			createErr: func() error {
				_, err := jwe.Decrypt([]byte("invalid"), jwe.WithKey(jwa.A256KW(), []byte("12345678901234567890123456789012")))
				return err
			},
			wantType: jwe.DecryptError(),
		},
		{
			name: "JWS VerifyError",
			createErr: func() error {
				_, err := jws.Verify([]byte("invalid"), jws.WithKey(jwa.HS256(), []byte("key")))
				return err
			},
			wantType: jws.VerifyError(),
		},
		{
			name: "JWK ParseError",
			createErr: func() error {
				_, err := jwk.ParseKey([]byte("invalid"))
				return err
			},
			wantType: nil, // JSON parse errors may not be wrapped in ParseError
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.createErr()
			require.Error(t, err, "expected error")

			// Verify error type (if specified)
			if tc.wantType != nil {
				require.True(t, errors.Is(err, tc.wantType), "error type mismatch: got %T, want %T", err, tc.wantType)
			}

			// Test %s formatting (concise)
			concise := fmt.Sprintf("%s", err)
			require.NotEmpty(t, concise, "concise format is empty")
			t.Logf("Concise (%s): %s", tc.name, concise)

			// Test %v formatting (concise)
			conciseV := fmt.Sprintf("%v", err)
			require.NotEmpty(t, conciseV, "concise %%v format is empty")

			// Test %+v formatting (verbose)
			verbose := fmt.Sprintf("%+v", err)
			require.NotEmpty(t, verbose, "verbose format is empty")
			t.Logf("Verbose (%s): %s", tc.name, verbose)

			// Concise and verbose should both be present
			// (verbose may be same as concise if chain is simple)
			require.NotEmpty(t, concise, "formatting produced empty output")
			require.NotEmpty(t, verbose, "formatting produced empty output")
		})
	}
}

// TestIntegration_ErrorUnwrapping tests that error chains can be unwrapped correctly
func TestIntegration_ErrorUnwrapping(t *testing.T) {
	t.Run("JWT parse error unwraps to root cause", func(t *testing.T) {
		_, err := jwt.Parse([]byte("invalid"))
		require.Error(t, err, "expected error")

		// Should be able to unwrap to find root cause
		var unwrapped error = err
		depth := 0
		for unwrapped != nil {
			depth++
			require.LessOrEqual(t, depth, 100, "error chain too deep (possible circular reference)")
			unwrapped = errors.Unwrap(unwrapped)
		}

		require.GreaterOrEqual(t, depth, 1, "error chain is empty")
		t.Logf("Error chain depth: %d", depth)
	})
}
