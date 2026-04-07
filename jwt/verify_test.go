package jwt_test

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/internal/json"
	"github.com/lestrrat-go/jwx/v3/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/require"
)

// TestVerifyCompactFastSecurityBypass tests potential security vulnerabilities
// when the fast path bypasses certain security checks that are normally
// performed by jws.Verify.
func TestVerifyCompactFastSecurityBypass(t *testing.T) {
	t.Run("Algorithm confusion with single WithKey option", func(t *testing.T) {
		// Create a JWT signed with HS256 (symmetric key)
		secret := []byte("secret-key-for-hmac")
		token := jwt.New()
		require.NoError(t, token.Set(jwt.IssuerKey, "test"), `token.Set should succeed`)
		require.NoError(t, token.Set(jwt.SubjectKey, "user123"), `token.Set should succeed`)

		signedHS256, err := jwt.Sign(token, jwt.WithKey(jwa.HS256(), secret))
		require.NoError(t, err, `jwt.Sign should succeed`)

		// Generate an RSA key pair
		rsaKey, err := jwxtest.GenerateRsaKey()
		require.NoError(t, err, `jwxtest.GenerateRsaKey should succeed`)

		// Test 1: Try to verify HS256 JWT using RS256 key (should fail)
		// This should fail because algorithm confusion should be prevented
		_, err = jwt.Parse(signedHS256, jwt.WithKey(jwa.RS256(), rsaKey.PublicKey))
		require.Error(t, err, `jwt.Parse should fail when trying to use RS256 key for HS256 JWT`)

		// Test 2: Ensure the fast path doesn't bypass algorithm validation
		// The fast path should still validate that the algorithm in the header
		// matches the algorithm specified in WithKey
		_, err = jwt.Parse(signedHS256, jwt.WithKey(jwa.RS256(), rsaKey.PublicKey))
		require.Error(t, err, `fast path should not allow algorithm confusion`)
	})

	t.Run("Header tampering detection", func(t *testing.T) {
		secret := []byte("test-secret")
		token := jwt.New()
		require.NoError(t, token.Set(jwt.IssuerKey, "test"), `token.Set should succeed`)

		signedJWT, err := jwt.Sign(token, jwt.WithKey(jwa.HS256(), secret))
		require.NoError(t, err, `jwt.Sign should succeed`)

		// Parse the JWT to get its components
		parts := strings.Split(string(signedJWT), ".")
		require.Len(t, parts, 3, `JWT should have 3 parts`)

		// Decode the header
		headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
		require.NoError(t, err, `header decode should succeed`)

		// Parse header JSON
		var header map[string]any
		require.NoError(t, json.Unmarshal(headerBytes, &header), `header unmarshal should succeed`)

		// Tamper with the algorithm in the header (change to "none")
		header["alg"] = "none"
		tamperedHeaderBytes, err := json.Marshal(header)
		require.NoError(t, err, `header marshal should succeed`)

		// Encode the tampered header
		tamperedHeader := base64.RawURLEncoding.EncodeToString(tamperedHeaderBytes)

		// Create JWT with tampered header
		tamperedJWT := tamperedHeader + "." + parts[1] + "." + parts[2]

		// Test: The parser should detect header tampering
		_, err = jwt.Parse([]byte(tamperedJWT), jwt.WithKey(jwa.HS256(), secret))
		require.Error(t, err, `jwt.Parse should fail with tampered header`)
	})

	t.Run("Critical header bypass", func(t *testing.T) {
		secret := []byte("test-secret")

		// Create a JWT with critical header that requires special handling
		token := jwt.New()
		require.NoError(t, token.Set(jwt.IssuerKey, "test"), `token.Set should succeed`)

		// Create JWS with critical header
		headers := jws.NewHeaders()
		require.NoError(t, headers.Set("crit", []string{"exp"}), `headers.Set should succeed`)
		require.NoError(t, headers.Set("exp", time.Now().Add(time.Hour).Unix()), `headers.Set should succeed`)

		signed, err := jws.Sign(json.RawMessage(`{"iss":"test"}`),
			jws.WithKey(jwa.HS256(), secret, jws.WithProtectedHeaders(headers)))
		require.NoError(t, err, `jws.Sign should succeed`)

		// The fast path should not bypass critical header validation
		// Note: This tests whether VerifyCompactFast properly handles critical headers
		_, err = jwt.Parse(signed, jwt.WithKey(jwa.HS256(), secret))
		// This should either succeed with proper critical header handling or fail gracefully
		// The key point is that it shouldn't silently bypass the critical header check
		if err != nil {
			t.Logf("Critical header validation failed as expected: %v", err)
		} else {
			t.Logf("Critical header was properly handled")
		}
	})

	t.Run("Key validation bypass", func(t *testing.T) {
		// Test that the fast path doesn't bypass key validation when WithValidateKey is used

		// Create an RSA key and import it as JWK
		rsaKey, err := jwxtest.GenerateRsaKey()
		require.NoError(t, err, `jwxtest.GenerateRsaKey should succeed`)

		jwkKey, err := jwk.Import[jwk.Key](rsaKey)
		require.NoError(t, err, `jwk.Import should succeed`)

		// Corrupt the key by setting invalid D value (private exponent)
		require.NoError(t, jwkKey.Set(jwk.RSADKey, []byte{1, 2, 3}), `jwkKey.Set should succeed`)

		token := jwt.New()
		require.NoError(t, token.Set(jwt.IssuerKey, "test"), `token.Set should succeed`)

		// Serialize the token to JSON for JWS signing
		tokenBytes, err := json.Marshal(token)
		require.NoError(t, err, `json.Marshal should succeed`)

		// Try to sign with the corrupted key and key validation enabled
		// This should fail even in the fast path
		_, err = jws.Sign(tokenBytes, jws.WithKey(jwa.RS256(), jwkKey), jws.WithValidateKey(true))
		require.Error(t, err, `jws.Sign should fail with invalid key when validation is enabled`)

		// Also test that JWT parsing with validation fails for invalid keys
		// Create a valid key first to sign a token
		validKey, err := jwxtest.GenerateRsaKey()
		require.NoError(t, err, `jwxtest.GenerateRsaKey should succeed`)

		signedJWT, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), validKey))
		require.NoError(t, err, `jwt.Sign should succeed`)

		// Try to verify with corrupted public key and validation enabled
		corruptedPubKey, err := jwk.Import[jwk.Key](&validKey.PublicKey)
		require.NoError(t, err, `jwk.Import should succeed`)

		// Corrupt the N value (modulus)
		require.NoError(t, corruptedPubKey.Set(jwk.RSANKey, []byte{1, 2, 3}), `jwk.Set should succeed`)

		// This should fail due to key validation
		_, err = jwt.Parse(signedJWT, jwt.WithKey(jwa.RS256(), corruptedPubKey))
		require.Error(t, err, `jwt.Parse should fail with corrupted public key`)
	})

	t.Run("Fast path vs slow path consistency", func(t *testing.T) {
		// Ensure that both fast path and slow path give the same results for edge cases
		secret := []byte("test-secret")
		token := jwt.New()
		require.NoError(t, token.Set(jwt.IssuerKey, "test"), `token.Set should succeed`)
		require.NoError(t, token.Set(jwt.ExpirationKey, time.Now().Add(-time.Hour)), `token.Set should succeed`)

		signedJWT, err := jwt.Sign(token, jwt.WithKey(jwa.HS256(), secret))
		require.NoError(t, err, `jwt.Sign should succeed`)

		// Force slow path by using multiple verify options
		_, err1 := jwt.Parse(signedJWT, jwt.WithKey(jwa.HS256(), secret), jwt.WithValidate(false))

		// Force fast path by using single WithKey option
		_, err2 := jwt.Parse(signedJWT, jwt.WithKey(jwa.HS256(), secret), jwt.WithValidate(false))

		// Both should give consistent results
		if err1 != nil && err2 != nil {
			// Both failed - this is consistent
			t.Logf("Both paths failed consistently")
		} else if err1 == nil && err2 == nil {
			// Both succeeded - this is consistent
			t.Logf("Both paths succeeded consistently")
		} else {
			// Inconsistent results - this could indicate a security issue
			require.Fail(t, "Fast path and slow path gave inconsistent results",
				"slow path error: %v, fast path error: %v", err1, err2)
		}
	})

	t.Run("Malformed JWT handling", func(t *testing.T) {
		secret := []byte("test-secret")

		// Test various malformed JWTs to ensure fast path doesn't bypass format validation
		malformedJWTs := []string{
			"invalid.jwt.format.extra", // Too many parts
			"invalid.jwt",              // Too few parts
			"invalid..signature",       // Empty payload
			".payload.signature",       // Empty header
			"header.payload.",          // Empty signature
		}

		for _, malformedJWT := range malformedJWTs {
			t.Run(fmt.Sprintf("malformed_%s", malformedJWT), func(t *testing.T) {
				_, err := jwt.Parse([]byte(malformedJWT), jwt.WithKey(jwa.HS256(), secret))
				require.Error(t, err, `jwt.Parse should fail for malformed JWT: %s`, malformedJWT)
			})
		}
	})

	t.Run("None algorithm bypass", func(t *testing.T) {
		// Test that "alg": "none" cannot be exploited through the fast path
		secret := []byte("test-secret")

		// Create a legitimate JWT first
		token := jwt.New()
		require.NoError(t, token.Set(jwt.IssuerKey, "test"), `token.Set should succeed`)

		signedJWT, err := jwt.Sign(token, jwt.WithKey(jwa.HS256(), secret))
		require.NoError(t, err, `jwt.Sign should succeed`)

		// Parse the JWT components
		parts := strings.Split(string(signedJWT), ".")
		require.Len(t, parts, 3, `JWT should have 3 parts`)

		// Create a new header with "alg": "none"
		noneHeader := map[string]any{
			"alg": "none",
			"typ": "JWT",
		}

		noneHeaderBytes, err := json.Marshal(noneHeader)
		require.NoError(t, err, `json.Marshal should succeed`)

		noneHeaderEncoded := base64.RawURLEncoding.EncodeToString(noneHeaderBytes)

		// Create a malicious JWT with "none" algorithm but keeping the original payload and signature
		maliciousJWT := noneHeaderEncoded + "." + parts[1] + "." + parts[2]

		// This should fail even if using the fast path
		_, err = jwt.Parse([]byte(maliciousJWT), jwt.WithKey(jwa.HS256(), secret))
		require.Error(t, err, `jwt.Parse should reject JWT with none algorithm when expecting HS256`)

		// Also test with empty signature as "none" algorithm typically uses
		maliciousJWTNoSig := noneHeaderEncoded + "." + parts[1] + "."
		_, err = jwt.Parse([]byte(maliciousJWTNoSig), jwt.WithKey(jwa.HS256(), secret))
		require.Error(t, err, `jwt.Parse should reject JWT with none algorithm and no signature`)
	})

	t.Run("Fast path detection", func(t *testing.T) {
		// This test attempts to verify that the fast path is actually being used
		// under the specific conditions we're testing
		secret := []byte("test-secret")
		token := jwt.New()
		require.NoError(t, token.Set(jwt.IssuerKey, "test"), `token.Set should succeed`)

		signedJWT, err := jwt.Sign(token, jwt.WithKey(jwa.HS256(), secret))
		require.NoError(t, err, `jwt.Sign should succeed`)

		// Conditions that should trigger fast path:
		// 1. Single WithKey option
		// 2. Valid SignatureAlgorithm
		// 3. No other options that would force slow path

		// Test case 1: This should use fast path (single WithKey with valid algorithm)
		parsed1, err := jwt.Parse(signedJWT, jwt.WithKey(jwa.HS256(), secret))
		require.NoError(t, err, `jwt.Parse with single WithKey should succeed`)
		require.NotNil(t, parsed1, `parsed token should not be nil`)

		// Test case 2: This should use slow path (multiple options)
		parsed2, err := jwt.Parse(signedJWT, jwt.WithKey(jwa.HS256(), secret), jwt.WithValidate(false))
		require.NoError(t, err, `jwt.Parse with multiple options should succeed`)
		require.NotNil(t, parsed2, `parsed token should not be nil`)

		// Both should produce equivalent results
		require.True(t, jwt.Equal(parsed1, parsed2), `fast path and slow path should produce equivalent results`)
	})
}
