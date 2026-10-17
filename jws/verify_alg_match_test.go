package jws_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
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

	t.Run("alg only in unprotected header is rejected", func(t *testing.T) {
		t.Parallel()
		// Flattened JSON JWS: protected header carries no "alg" (it is in
		// the unprotected header). The signature is valid HMAC, but the
		// unprotected header is not covered by it, so "alg" must not be
		// taken from there.
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

		_, err = jws.Verify(jsonJWS, jws.WithKey(jwa.HS256(), hmacKey))
		require.Error(t, err, `alg-in-unprotected JWS should be rejected`)
		require.ErrorIs(t, err, jws.VerifyError())

		_, err = jws.Verify(jsonJWS, jws.WithKey(jwa.HS256(), hmacKey), jws.WithSkipAlgorithmMatch(true))
		require.Error(t, err, `WithSkipAlgorithmMatch must not make a missing protected alg acceptable`)
		require.ErrorIs(t, err, jws.VerifyError())
	})

	t.Run("omitted protected member is rejected", func(t *testing.T) {
		t.Parallel()
		// No "protected" member at all: RFC 7515 section 5.1 signs over an
		// empty protected segment, and "alg" can only be in the unprotected
		// header. The result is rejected for lack of a protected "alg".
		pl := b64url(payload)
		mac := hmac.New(sha256.New, hmacKey)
		_, err := mac.Write([]byte("." + pl))
		require.NoError(t, err, `hmac write should succeed`)

		jsonJWS := []byte(`{"header":{"alg":"HS256"},"payload":"` + pl +
			`","signature":"` + b64url(mac.Sum(nil)) + `"}`)

		_, err = jws.Verify(jsonJWS, jws.WithKey(jwa.HS256(), hmacKey))
		require.Error(t, err, `omitted protected member should be rejected`)
		require.ErrorIs(t, err, jws.VerifyError())
	})

	t.Run("compact protected header without alg is rejected", func(t *testing.T) {
		t.Parallel()
		hdr := b64url([]byte(`{"typ":"JWT"}`))
		pl := b64url(payload)
		mac := hmac.New(sha256.New, hmacKey)
		_, err := mac.Write([]byte(hdr + "." + pl))
		require.NoError(t, err, `hmac write should succeed`)

		token := []byte(hdr + "." + pl + "." + b64url(mac.Sum(nil)))
		_, err = jws.Verify(token, jws.WithKey(jwa.HS256(), hmacKey))
		require.Error(t, err, `compact JWS without protected alg should be rejected`)
		require.ErrorIs(t, err, jws.VerifyError())
	})

	t.Run("EdDSA and Ed25519 are distinct per RFC 9864", func(t *testing.T) {
		t.Parallel()
		// RFC 9864 deprecates the polymorphic "EdDSA" in favor of the
		// fully-specified "Ed25519"/"Ed448". They are distinct identifiers and
		// do NOT alias one another: cross-identifier verification requires a
		// matching alg or jws.WithSkipAlgorithmMatch(true).
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err, `ed25519 key generation should succeed`)

		// Sign with the polymorphic "EdDSA" identifier; header alg is "EdDSA".
		signed, err := jws.Sign(payload, jws.WithKey(jwa.EdDSA(), priv))
		require.NoError(t, err, `jws.Sign with EdDSA should succeed`)

		// Verifying under the fully-specified "Ed25519" identifier is rejected
		// by default: "EdDSA" != "Ed25519".
		_, err = jws.Verify(signed, jws.WithKey(jwa.EdDSAEd25519(), pub))
		require.Error(t, err, `cross-identifier verify should be rejected by default`)
		require.ErrorIs(t, err, jws.VerifyError())

		// The same crypto verifies when the algorithm matches the header...
		got, err := jws.Verify(signed, jws.WithKey(jwa.EdDSA(), pub))
		require.NoError(t, err, `matching-alg verify should succeed`)
		require.Equal(t, payload, got)

		// ...or when the alg-match check is explicitly skipped.
		got, err = jws.Verify(signed, jws.WithKey(jwa.EdDSAEd25519(), pub), jws.WithSkipAlgorithmMatch(true))
		require.NoError(t, err, `WithSkipAlgorithmMatch should verify the same crypto`)
		require.Equal(t, payload, got)
	})
}

// makeAlgConfusedDetachedCompact builds a compact detached JWS whose protected
// header advertises headerAlg but whose signature is a valid HMAC-SHA256 over
// the detached signing input base64(protected) "." base64(payload). It mirrors
// makeAlgConfusedCompact but omits the payload segment so the result can be
// verified through the WithDetachedPayloadReader streaming path.
func makeAlgConfusedDetachedCompact(t *testing.T, headerAlg string, payload, hmacKey []byte) []byte {
	t.Helper()
	hdr := b64url([]byte(`{"alg":"` + headerAlg + `"}`))
	pl := b64url(payload)
	signingInput := hdr + "." + pl

	mac := hmac.New(sha256.New, hmacKey)
	_, err := mac.Write([]byte(signingInput))
	require.NoError(t, err, `hmac write should succeed`)
	sig := mac.Sum(nil)

	// Compact detached form: header ".." signature (empty payload segment).
	return []byte(hdr + ".." + b64url(sig))
}

// TestVerifyAlgorithmMatchStreaming covers the WithDetachedPayloadReader
// (streaming) path, which bypasses verifyContext.tryKey and so needs its own
// alg-match guard.
func TestVerifyAlgorithmMatchStreaming(t *testing.T) {
	t.Parallel()

	payload := []byte("hello world")
	hmacKey := []byte("0123456789abcdef0123456789abcdef") // 32 bytes

	t.Run("default rejects header alg mismatching verification alg", func(t *testing.T) {
		t.Parallel()
		token := makeAlgConfusedDetachedCompact(t, "RS256", payload, hmacKey)

		// Sanity: the signature is valid HMAC-SHA256, so with the guard
		// bypassed it verifies through the streaming path.
		_, err := jws.Verify(token,
			jws.WithKey(jwa.HS256(), hmacKey),
			jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
			jws.WithSkipAlgorithmMatch(true),
		)
		require.NoError(t, err, `streaming verify with skip should succeed (signature is valid HMAC)`)

		// Default behavior: rejected because header "alg" (RS256) does not
		// match the verification algorithm (HS256).
		_, err = jws.Verify(token,
			jws.WithKey(jwa.HS256(), hmacKey),
			jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
		)
		require.Error(t, err, `streaming default verification should reject alg mismatch`)
		require.ErrorIs(t, err, jws.VerifyError())
	})

	t.Run("opt-out bypasses the check", func(t *testing.T) {
		t.Parallel()
		token := makeAlgConfusedDetachedCompact(t, "RS256", payload, hmacKey)

		_, err := jws.Verify(token,
			jws.WithKey(jwa.HS256(), hmacKey),
			jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
			jws.WithSkipAlgorithmMatch(true),
		)
		require.NoError(t, err, `streaming verify with WithSkipAlgorithmMatch(true) should succeed`)
	})

	t.Run("protected header without alg is rejected", func(t *testing.T) {
		t.Parallel()
		hdr := b64url([]byte(`{"typ":"JWT"}`))
		mac := hmac.New(sha256.New, hmacKey)
		_, err := mac.Write([]byte(hdr + "." + b64url(payload)))
		require.NoError(t, err, `hmac write should succeed`)

		token := []byte(hdr + ".." + b64url(mac.Sum(nil)))
		for _, skip := range []bool{false, true} {
			_, err = jws.Verify(token,
				jws.WithKey(jwa.HS256(), hmacKey),
				jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
				jws.WithSkipAlgorithmMatch(skip),
			)
			require.Error(t, err, `streaming verify without protected alg should be rejected (skip=%v)`, skip)
			require.ErrorIs(t, err, jws.VerifyError())
		}
	})

	t.Run("matching alg verifies (no regression)", func(t *testing.T) {
		t.Parallel()
		signed, err := jws.Sign(nil,
			jws.WithKey(jwa.HS256(), hmacKey),
			jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
		)
		require.NoError(t, err, `streaming jws.Sign should succeed`)

		_, err = jws.Verify(signed,
			jws.WithKey(jwa.HS256(), hmacKey),
			jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
		)
		require.NoError(t, err, `streaming verify with matching alg should succeed`)
	})
}
