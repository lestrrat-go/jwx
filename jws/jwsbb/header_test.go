package jwsbb_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/base64"
	"github.com/lestrrat-go/jwx/v4/jws/jwsbb"
	"github.com/stretchr/testify/require"
)

func TestHeader(t *testing.T) {
	t.Parallel()

	// Test basic header parsing
	t.Run("HeaderParseCompact", func(t *testing.T) {
		t.Parallel()
		// Base64URL encoded {"alg":"HS256","typ":"JWT","kid":"test-key"}
		headerJSON := `{"alg":"HS256","typ":"JWT","kid":"test-key"}`
		headerB64 := base64.DefaultEncoder().EncodeToString([]byte(headerJSON))

		header := jwsbb.HeaderParseCompact([]byte(headerB64))
		require.NotNil(t, header, "HeaderParseCompact should return a valid header")

		// Test HeaderGetString
		alg, err := jwsbb.HeaderGetString(header, "alg")
		require.NoError(t, err, "HeaderGetString should not return error")
		require.Equal(t, "HS256", alg, "alg should be HS256")

		typ, err := jwsbb.HeaderGetString(header, "typ")
		require.NoError(t, err, "HeaderGetString should not return error")
		require.Equal(t, "JWT", typ, "typ should be JWT")

		kid, err := jwsbb.HeaderGetString(header, "kid")
		require.NoError(t, err, "HeaderGetString should not return error")
		require.Equal(t, "test-key", kid, "kid should be test-key")

		// Test non-existent field
		nonExistent, err := jwsbb.HeaderGetString(header, "nonexistent")
		require.Error(t, err, "HeaderGetString should not return error for non-existent field")
		require.Equal(t, "", nonExistent, "non-existent field should return empty string")
	})

	t.Run("HeaderGetBool", func(t *testing.T) {
		t.Parallel()
		headerJSON := `{"debug":true,"enabled":false}`
		headerB64 := base64.DefaultEncoder().EncodeToString([]byte(headerJSON))
		header := jwsbb.HeaderParseCompact([]byte(headerB64))

		debug, err := jwsbb.HeaderGetBool(header, "debug")
		require.NoError(t, err, "HeaderGetBool should not return error")
		require.True(t, debug, "debug should be true")

		enabled, err := jwsbb.HeaderGetBool(header, "enabled")
		require.NoError(t, err, "HeaderGetBool should not return error")
		require.False(t, enabled, "enabled should be false")
	})

	t.Run("HeaderGetInt", func(t *testing.T) {
		t.Parallel()
		headerJSON := `{"count":42,"negative":-10}`
		headerB64 := base64.DefaultEncoder().EncodeToString([]byte(headerJSON))

		header := jwsbb.HeaderParseCompact([]byte(headerB64))

		count, err := jwsbb.HeaderGetInt(header, "count")
		require.NoError(t, err, "HeaderGetInt should not return error")
		require.Equal(t, 42, count, "count should be 42")

		negative, err := jwsbb.HeaderGetInt(header, "negative")
		require.NoError(t, err, "HeaderGetInt should not return error")
		require.Equal(t, -10, negative, "negative should be -10")
	})

	t.Run("HeaderGetFloat64", func(t *testing.T) {
		t.Parallel()
		headerJSON := `{"pi":3.14159,"ratio":2.5}`
		headerB64 := base64.DefaultEncoder().EncodeToString([]byte(headerJSON))

		header := jwsbb.HeaderParseCompact([]byte(headerB64))

		pi, err := jwsbb.HeaderGetFloat64(header, "pi")
		require.NoError(t, err, "HeaderGetFloat64 should not return error")
		require.Equal(t, 3.14159, pi, "pi should be 3.14159")

		ratio, err := jwsbb.HeaderGetFloat64(header, "ratio")
		require.NoError(t, err, "HeaderGetFloat64 should not return error")
		require.Equal(t, 2.5, ratio, "ratio should be 2.5")
	})

	t.Run("HeaderWithKidLookupAndVerification", func(t *testing.T) {
		t.Parallel()
		// Generate RSA key pairs for signing
		rsaKey1, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err, "RSA key generation should not error")

		rsaKey2, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err, "RSA key generation should not error")

		// Create a simple key map for lookup with different keys
		keyMap := map[string]crypto.PublicKey{
			"key-1": &rsaKey1.PublicKey,
			"key-2": &rsaKey2.PublicKey,
		}

		var signed []byte
		{ // First part: sign the payload
			// Create JWS header with kid
			headerJSON := `{"alg":"RS256","typ":"JWT","kid":"key-1"}`

			// Create payload
			payload := []byte("test payload")

			// Create signature input using SignBuffer
			encoder := base64.DefaultEncoder()
			signInput := jwsbb.SignBuffer(nil, []byte(headerJSON), payload, encoder, true)

			// Sign with RSA using jwsbb.SignRSA
			signature, err := jwsbb.SignRSA(rsaKey1, signInput, crypto.SHA256, false, nil)
			require.NoError(t, err, "RSA signing should not error")

			// Create full JWS compact format using JoinCompact
			v, err := jwsbb.JoinCompact(nil, []byte(headerJSON), payload, signature, encoder, true)
			require.NoError(t, err, "JoinCompact should not error")
			signed = v
		}

		{
			// Work with the signed compact JWS
			// Parse header and extract kid
			headerB64, payloadB64, signatureB64, err := jwsbb.SplitCompact(signed)
			require.NoError(t, err, "SplitCompact should not return error")

			header := jwsbb.HeaderParseCompact(headerB64)
			kid, err := jwsbb.HeaderGetString(header, "kid")
			require.NoError(t, err, "HeaderGetString should not return error for kid")
			require.Equal(t, "key-1", kid, "kid should be key-1")

			// Look up key using kid
			pubKey, exists := keyMap[kid]
			require.True(t, exists, "key should exist in keyMap")

			// Verify signature using the looked up key
			rsaPubKey, ok := pubKey.(*rsa.PublicKey)
			require.True(t, ok, "key should be RSA public key")

			// since the header/payload are already base64-encoded, we're just going
			// to craft them by hand
			signBuffer := append(append(headerB64, '.'), payloadB64...)

			signature, err := base64.Decode(signatureB64)
			require.NoError(t, err, "Base64 decoding of signature should not error")

			err = jwsbb.VerifyRSA(rsaPubKey, signBuffer, signature, crypto.SHA256, false)
			require.NoError(t, err, "RSA signature verification should succeed")
		}
	})

	t.Run("ErrorHandling", func(t *testing.T) {
		t.Parallel()

		t.Run("non-existent field", func(t *testing.T) {
			t.Parallel()
			headerJSON := `{"alg":"HS256","typ":"JWT"}`
			h := jwsbb.HeaderParse([]byte(headerJSON))
			_, err := jwsbb.HeaderGetString(h, "nonexistent")
			require.Error(t, err, "HeaderGetString should return error for non-existent field")
			require.ErrorIs(t, err, jwsbb.ErrHeaderNotFound(), "Error should be ErrHeaderNotFound")
		})
		t.Run("invalid JSON", func(t *testing.T) {
			t.Parallel()
			// Test invalid JSON
			invalidHeader := jwsbb.HeaderParseCompact([]byte("invalid-json"))

			_, err := jwsbb.HeaderGetString(invalidHeader, "alg")
			require.Error(t, err, "HeaderGetString should return error for invalid header")

			_, err = jwsbb.HeaderGetBool(invalidHeader, "debug")
			require.Error(t, err, "HeaderGetBool should return error for invalid header")

			_, err = jwsbb.HeaderGetInt(invalidHeader, "count")
			require.Error(t, err, "HeaderGetInt should return error for invalid header")

			_, err = jwsbb.HeaderGetFloat64(invalidHeader, "pi")
			require.Error(t, err, "HeaderGetFloat64 should return error for invalid header")

			_, err = jwsbb.HeaderGetStringBytes(invalidHeader, "data")
			require.Error(t, err, "HeaderGetStringBytes should return error for invalid header")

			_, err = jwsbb.HeaderGetUint(invalidHeader, "count")
			require.Error(t, err, "HeaderGetUint should return error for invalid header")

			_, err = jwsbb.HeaderGetInt64(invalidHeader, "timestamp")
			require.Error(t, err, "HeaderGetInt64 should return error for invalid header")

			_, err = jwsbb.HeaderGetUint64(invalidHeader, "timestamp")
			require.Error(t, err, "HeaderGetUint64 should return error for invalid header")
		})
	})
}
