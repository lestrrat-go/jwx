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

	t.Run("EdDSA header verifies under Ed25519 (RFC 9864 alias)", func(t *testing.T) {
		t.Parallel()
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err, `ed25519 key generation should succeed`)

		// Sign with the polymorphic "EdDSA" identifier; header alg is "EdDSA".
		signed, err := jws.Sign(payload, jws.WithKey(jwa.EdDSA(), priv))
		require.NoError(t, err, `jws.Sign with EdDSA should succeed`)

		// Verifying under the fully-specified "Ed25519" identifier must
		// succeed: RFC 9864 makes the two interchangeable.
		got, err := jws.Verify(signed, jws.WithKey(jwa.EdDSAEd25519(), pub))
		require.NoError(t, err, `EdDSA header should verify under Ed25519 alias`)
		require.Equal(t, payload, got)

		// And the reverse direction.
		signed, err = jws.Sign(payload, jws.WithKey(jwa.EdDSAEd25519(), priv))
		require.NoError(t, err, `jws.Sign with Ed25519 should succeed`)
		got, err = jws.Verify(signed, jws.WithKey(jwa.EdDSA(), pub))
		require.NoError(t, err, `Ed25519 header should verify under EdDSA alias`)
		require.Equal(t, payload, got)
	})
}

// ed25519BackedVerifier is a jws.Verifier that validates with crypto/ed25519.
// It lets a test register a synthetic fully-specified EdDSA identifier (e.g.
// "Ed448") backed by a genuine Ed25519 signature, so the end-to-end alg-match
// guard can be exercised without importing the real ed448 extension module.
type ed25519BackedVerifier struct{}

func (ed25519BackedVerifier) Verify(key any, payload, signature []byte) error {
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return errEd25519BackedVerifierKeyType
	}
	if !ed25519.Verify(pub, payload, signature) {
		return errEd25519BackedVerifierBadSig
	}
	return nil
}

var (
	errEd25519BackedVerifierKeyType = errEd25519Backed("ed25519BackedVerifier: key is not ed25519.PublicKey")
	errEd25519BackedVerifierBadSig  = errEd25519Backed("ed25519BackedVerifier: signature verification failed")
)

type errEd25519Backed string

func (e errEd25519Backed) Error() string { return string(e) }

// makeEdDSACurveConfusedCompact builds a compact JWS whose protected header
// advertises headerAlg but whose signature is a valid Ed25519 signature over
// the signing input. With headerAlg="Ed448" and an Ed25519 signing key the
// result is curve-confused: the header claims Ed448 while the key (and the
// actual signature) is Ed25519.
func makeEdDSACurveConfusedCompact(t *testing.T, headerAlg string, payload []byte, priv ed25519.PrivateKey) []byte {
	t.Helper()
	hdr := b64url([]byte(`{"alg":"` + headerAlg + `"}`))
	pl := b64url(payload)
	signingInput := hdr + "." + pl
	sig := ed25519.Sign(priv, []byte(signingInput))
	return []byte(signingInput + "." + b64url(sig))
}

// TestVerifyEdDSACurveAwareAlgMatch pins the KEY-AWARE behavior of the RFC 9864
// generic/specific EdDSA alias. The generic "EdDSA" identifier only aliases the
// fully-specified variant that the verification key actually is, so a protected
// header claiming "Ed448" must be rejected when the key is an Ed25519 key, even
// though the verifier was configured with the generic jwa.EdDSA(). A name-only
// alias would accept this and let a header advertise a curve the key cannot be.
//
// It registers a synthetic "Ed448" SignatureAlgorithm backed by an Ed25519
// verifier (and deliberately does NOT register the Ed448 curve, mirroring an
// environment where AlgorithmsForKey can only resolve an Ed25519 key to
// "Ed25519"). Because it mutates the process-global algorithm registry, this
// test must not run in parallel and cleans up after itself.
func TestVerifyEdDSACurveAwareAlgMatch(t *testing.T) {
	payload := []byte("hello world")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err, `ed25519 key generation should succeed`)

	// Register a synthetic, parseable "Ed448" identifier backed by an Ed25519
	// verifier. We do NOT register an Ed448 curve, so AlgorithmsForKey resolves
	// the Ed25519 key only to "Ed25519" — exactly the signal the guard relies
	// on to reject the curve-confused header.
	ed448 := jwa.NewSignatureAlgorithm("Ed448")
	require.NoError(t, jws.RegisterVerifier(ed448, ed25519BackedVerifier{}),
		`registering synthetic Ed448 verifier should succeed`)
	t.Cleanup(func() {
		_ = jws.UnregisterVerifier(ed448)
		jwa.UnregisterSignatureAlgorithm(ed448)
	})

	t.Run("Ed448 header with generic EdDSA verifier + Ed25519 key rejects (tryKey)", func(t *testing.T) {
		// Header claims Ed448; signature is genuine Ed25519; verifier uses the
		// generic jwa.EdDSA() with an Ed25519 key. The name-only alias would
		// pass ("Ed448" aliases "EdDSA"), but the key is Ed25519, so it must
		// be rejected.
		token := makeEdDSACurveConfusedCompact(t, "Ed448", payload, priv)

		_, err := jws.Verify(token, jws.WithKey(jwa.EdDSA(), pub))
		require.Error(t, err, `Ed448 header with Ed25519 key must be rejected`)
		require.ErrorIs(t, err, jws.VerifyError())

		// Sanity: the signature really is a valid Ed25519 signature. With the
		// alg-match guard bypassed it verifies (proving the rejection above is
		// the guard firing, not a bad signature).
		_, err = jws.Verify(token, jws.WithKey(jwa.EdDSA(), pub), jws.WithSkipAlgorithmMatch(true))
		require.NoError(t, err, `signature is valid Ed25519; skip should verify`)
	})

	t.Run("Ed448 header with specific Ed448 verifier + Ed25519 key rejects (tryKey)", func(t *testing.T) {
		// Exact header/verifier match ("Ed448"/"Ed448") is allowed by the
		// name-only equality branch and is NOT what this fix touches — that is
		// the operator pinning the synthetic Ed448 algorithm explicitly. The
		// fix specifically targets the generic-EdDSA-verifier-vs-Ed448-header
		// case above, where the verifier did not pin the curve.
		token := makeEdDSACurveConfusedCompact(t, "Ed448", payload, priv)
		_, err := jws.Verify(token, jws.WithKey(ed448, pub))
		require.NoError(t, err, `exact Ed448/Ed448 with a matching verifier should verify`)
	})

	t.Run("Ed25519 header with generic EdDSA verifier + Ed25519 key verifies", func(t *testing.T) {
		t.Parallel()
		// Generic verifier, specific (matching-curve) header: the alias holds.
		signed, err := jws.Sign(payload, jws.WithKey(jwa.EdDSAEd25519(), priv))
		require.NoError(t, err, `jws.Sign with Ed25519 should succeed`)

		got, err := jws.Verify(signed, jws.WithKey(jwa.EdDSA(), pub))
		require.NoError(t, err, `Ed25519 header should verify under generic EdDSA with an Ed25519 key`)
		require.Equal(t, payload, got)
	})

	t.Run("EdDSA header with specific Ed25519 verifier + Ed25519 key verifies", func(t *testing.T) {
		t.Parallel()
		signed, err := jws.Sign(payload, jws.WithKey(jwa.EdDSA(), priv))
		require.NoError(t, err, `jws.Sign with EdDSA should succeed`)

		got, err := jws.Verify(signed, jws.WithKey(jwa.EdDSAEd25519(), pub))
		require.NoError(t, err, `EdDSA header should verify under specific Ed25519 with an Ed25519 key`)
		require.Equal(t, payload, got)
	})

	t.Run("exact EdDSA header and EdDSA verifier verifies", func(t *testing.T) {
		t.Parallel()
		signed, err := jws.Sign(payload, jws.WithKey(jwa.EdDSA(), priv))
		require.NoError(t, err, `jws.Sign with EdDSA should succeed`)

		got, err := jws.Verify(signed, jws.WithKey(jwa.EdDSA(), pub))
		require.NoError(t, err, `exact EdDSA/EdDSA should verify`)
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
