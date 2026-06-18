package jws_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/require"
)

// b64 is RFC 7515 base64url, no padding.
func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// makeAlgConfusedCompact builds a compact JWS whose protected header
// advertises `headerAlg` but whose signature is actually a valid
// HMAC-SHA256 over the signing input computed with `hmacKey`. The result
// verifies cryptographically under HS256 even though the header claims a
// different algorithm.
func makeAlgConfusedCompact(t *testing.T, headerAlg string, payload, hmacKey []byte) []byte {
	t.Helper()
	hdr := b64url([]byte(`{"alg":"` + headerAlg + `"}`))
	pl := b64url(payload)
	signingInput := hdr + "." + pl

	mac := hmac.New(sha256.New, hmacKey)
	_, err := mac.Write([]byte(signingInput))
	require.NoError(t, err, `hmac write should succeed`)
	sig := mac.Sum(nil)

	return []byte(signingInput + "." + b64url(sig))
}

func TestVerifyAlgorithmMatch(t *testing.T) {
	t.Parallel()

	payload := []byte("hello world")
	hmacKey := []byte("0123456789abcdef0123456789abcdef") // 32 bytes

	t.Run("default rejects header alg mismatching verification alg", func(t *testing.T) {
		t.Parallel()
		// Protected header advertises RS256 but the signature is a valid
		// HMAC-SHA256, so verifying under HS256 succeeds cryptographically.
		token := makeAlgConfusedCompact(t, "RS256", payload, hmacKey)

		// Sanity: the signature really is valid HMAC-SHA256 (i.e. without
		// the alg-match guard this would have verified). We confirm by
		// using the opt-out below, which bypasses only the alg-match check.
		got, err := jws.Verify(token, jws.WithKey(jwa.HS256(), hmacKey), jws.WithSkipAlgorithmMatch(true))
		require.NoError(t, err, `verification with skip should succeed (signature is valid HMAC)`)
		require.Equal(t, payload, got)

		// Default behavior: rejected because header "alg" (RS256) does not
		// match the verification algorithm (HS256).
		_, err = jws.Verify(token, jws.WithKey(jwa.HS256(), hmacKey))
		require.Error(t, err, `default verification should reject alg mismatch`)
		require.ErrorIs(t, err, jws.VerifyError())
	})

	t.Run("opt-out bypasses the check", func(t *testing.T) {
		t.Parallel()
		token := makeAlgConfusedCompact(t, "RS256", payload, hmacKey)

		got, err := jws.Verify(token, jws.WithKey(jwa.HS256(), hmacKey), jws.WithSkipAlgorithmMatch(true))
		require.NoError(t, err, `verification with WithSkipAlgorithmMatch(true) should succeed`)
		require.Equal(t, payload, got)
	})

	t.Run("matching alg verifies (no regression)", func(t *testing.T) {
		t.Parallel()
		// Normal sign with HS256 -> header alg HS256 -> verifies fine.
		signed, err := jws.Sign(payload, jws.WithKey(jwa.HS256(), hmacKey))
		require.NoError(t, err, `jws.Sign should succeed`)

		got, err := jws.Verify(signed, jws.WithKey(jwa.HS256(), hmacKey))
		require.NoError(t, err, `verification with matching alg should succeed`)
		require.Equal(t, payload, got)
	})

	t.Run("alg only in unprotected header falls through", func(t *testing.T) {
		t.Parallel()
		// Flattened JSON JWS: protected header carries no "alg" (it is in
		// the unprotected header). The signing input is computed over the
		// empty protected header. The alg-match guard must NOT fire here,
		// since the protected header has no "alg" to contradict.
		protected := b64url([]byte(`{}`))
		pl := b64url(payload)
		signingInput := protected + "." + pl

		mac := hmac.New(sha256.New, hmacKey)
		_, err := mac.Write([]byte(signingInput))
		require.NoError(t, err, `hmac write should succeed`)
		sig := mac.Sum(nil)

		jsonJWS := []byte(`{"protected":"` + protected +
			`","header":{"alg":"HS256"},"payload":"` + pl +
			`","signature":"` + b64url(sig) + `"}`)

		got, err := jws.Verify(jsonJWS, jws.WithKey(jwa.HS256(), hmacKey))
		require.NoError(t, err, `alg-in-unprotected JWS should verify (falls through)`)
		require.Equal(t, payload, got)
	})
}
