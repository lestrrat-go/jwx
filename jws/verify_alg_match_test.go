package jws_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/stretchr/testify/require"
)

// b64url is RFC 7515 base64url, no padding.
func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// makeAlgConfusedCompact builds a compact JWS whose protected header is
// `header` but whose signature is a valid HMAC-SHA256 over the signing input
// computed with `hmacKey`. When the header advertises another algorithm, the
// result still verifies cryptographically under HS256.
func makeAlgConfusedCompact(t *testing.T, header string, payload, hmacKey []byte) []byte {
	t.Helper()
	hdr := b64url([]byte(header))
	pl := b64url(payload)
	signingInput := hdr + "." + pl

	mac := hmac.New(sha256.New, hmacKey)
	_, err := mac.Write([]byte(signingInput))
	require.NoError(t, err, `hmac write should succeed`)
	sig := mac.Sum(nil)

	return []byte(signingInput + "." + b64url(sig))
}

// hs256KeyProvider hands out one HS256 key regardless of the message, so the
// alg-match check is exercised for custom key providers too.
type hs256KeyProvider struct {
	key []byte
}

func (kp hs256KeyProvider) FetchKeys(_ context.Context, sink jws.KeySink, _ *jws.Signature, _ *jws.Message) error {
	sink.Key(jwa.HS256(), kp.key)
	return nil
}

func TestVerifyAlgorithmMatch(t *testing.T) {
	t.Parallel()

	payload := []byte("hello world")
	hmacKey := []byte("0123456789abcdef0123456789abcdef") // 32 bytes

	jwkKey, err := jwk.Import(hmacKey)
	require.NoError(t, err, `jwk.Import should succeed`)
	require.NoError(t, jwkKey.Set(jwk.KeyIDKey, "k1"), `setting kid should succeed`)
	require.NoError(t, jwkKey.Set(jwk.AlgorithmKey, jwa.HS256()), `setting alg should succeed`)
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(jwkKey), `adding key to set should succeed`)

	keySources := []struct {
		name   string
		option jws.VerifyOption
	}{
		{name: "WithKey", option: jws.WithKey(jwa.HS256(), hmacKey)},
		{name: "WithKeySet", option: jws.WithKeySet(set)},
		{name: "WithKeyProvider", option: jws.WithKeyProvider(hs256KeyProvider{key: hmacKey})},
	}

	t.Run("default accepts header alg mismatching verification alg", func(t *testing.T) {
		t.Parallel()
		// The protected header advertises RS256, but the signature is a valid
		// HMAC-SHA256. v3 verifies under the algorithm from the key source
		// and ignores the header "alg" unless WithAlgorithmMatch(true) is
		// passed.
		token := makeAlgConfusedCompact(t, `{"alg":"RS256","kid":"k1"}`, payload, hmacKey)

		for _, src := range keySources {
			got, err := jws.Verify(token, src.option)
			require.NoError(t, err, `default verification with %s should not compare header alg`, src.name)
			require.Equal(t, payload, got)
		}
	})

	t.Run("WithAlgorithmMatch(true) rejects header alg mismatching verification alg", func(t *testing.T) {
		t.Parallel()
		token := makeAlgConfusedCompact(t, `{"alg":"RS256","kid":"k1"}`, payload, hmacKey)

		for _, src := range keySources {
			_, err := jws.Verify(token, src.option, jws.WithAlgorithmMatch(true))
			require.Error(t, err, `verification with %s should reject alg mismatch`, src.name)
			require.ErrorIs(t, err, jws.VerifyError())
		}
	})

	t.Run("WithAlgorithmMatch(false) keeps the default", func(t *testing.T) {
		t.Parallel()
		token := makeAlgConfusedCompact(t, `{"alg":"RS256","kid":"k1"}`, payload, hmacKey)

		got, err := jws.Verify(token, jws.WithKey(jwa.HS256(), hmacKey), jws.WithAlgorithmMatch(false))
		require.NoError(t, err, `WithAlgorithmMatch(false) should not compare header alg`)
		require.Equal(t, payload, got)
	})

	t.Run("matching alg verifies with WithAlgorithmMatch(true)", func(t *testing.T) {
		t.Parallel()
		signed, err := jws.Sign(payload, jws.WithKey(jwa.HS256(), hmacKey))
		require.NoError(t, err, `jws.Sign should succeed`)

		got, err := jws.Verify(signed, jws.WithKey(jwa.HS256(), hmacKey), jws.WithAlgorithmMatch(true))
		require.NoError(t, err, `verification with matching alg should succeed`)
		require.Equal(t, payload, got)
	})

	t.Run("missing protected alg verifies with WithAlgorithmMatch(true)", func(t *testing.T) {
		t.Parallel()
		// With no protected "alg" there is nothing to compare, so the
		// message verifies under the algorithm from the key source.
		token := makeAlgConfusedCompact(t, `{"kid":"k1"}`, payload, hmacKey)

		for _, src := range keySources {
			got, err := jws.Verify(token, src.option, jws.WithAlgorithmMatch(true))
			require.NoError(t, err, `verification with %s should succeed without a protected alg`, src.name)
			require.Equal(t, payload, got)
		}
	})

	t.Run("alg only in unprotected header is not compared", func(t *testing.T) {
		t.Parallel()
		// Flattened JSON JWS: the protected header carries no "alg". The
		// unprotected header is not integrity-protected, so its "alg" is not
		// compared, even when it disagrees with the verification algorithm.
		protected := b64url([]byte(`{}`))
		pl := b64url(payload)
		signingInput := protected + "." + pl

		mac := hmac.New(sha256.New, hmacKey)
		_, err := mac.Write([]byte(signingInput))
		require.NoError(t, err, `hmac write should succeed`)
		sig := mac.Sum(nil)

		jsonJWS := []byte(`{"protected":"` + protected +
			`","header":{"alg":"RS256"},"payload":"` + pl +
			`","signature":"` + b64url(sig) + `"}`)

		got, err := jws.Verify(jsonJWS, jws.WithKey(jwa.HS256(), hmacKey), jws.WithAlgorithmMatch(true))
		require.NoError(t, err, `unprotected alg should not be compared`)
		require.Equal(t, payload, got)
	})

	t.Run("EdDSA and Ed25519 are distinct per RFC 9864", func(t *testing.T) {
		t.Parallel()
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err, `ed25519 key generation should succeed`)

		// Sign with the polymorphic "EdDSA" identifier; header alg is "EdDSA".
		signed, err := jws.Sign(payload, jws.WithKey(jwa.EdDSA(), priv))
		require.NoError(t, err, `jws.Sign with EdDSA should succeed`)

		// By default v3 verifies under the fully-specified "Ed25519"
		// identifier without comparing it to the header.
		got, err := jws.Verify(signed, jws.WithKey(jwa.EdDSAEd25519(), pub))
		require.NoError(t, err, `cross-identifier verify should succeed by default`)
		require.Equal(t, payload, got)

		// With the check enabled, "EdDSA" != "Ed25519".
		_, err = jws.Verify(signed, jws.WithKey(jwa.EdDSAEd25519(), pub), jws.WithAlgorithmMatch(true))
		require.Error(t, err, `cross-identifier verify should be rejected with WithAlgorithmMatch(true)`)
		require.ErrorIs(t, err, jws.VerifyError())

		got, err = jws.Verify(signed, jws.WithKey(jwa.EdDSA(), pub), jws.WithAlgorithmMatch(true))
		require.NoError(t, err, `matching-alg verify should succeed`)
		require.Equal(t, payload, got)
	})
}

// makeAlgConfusedDetachedCompact builds a compact detached JWS whose protected
// header advertises headerAlg but whose signature is a valid HMAC-SHA256 over
// the detached signing input base64(protected) "." base64(payload).
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
// (streaming) path, which does not go through the per-key verification loop
// and so needs its own alg-match check.
func TestVerifyAlgorithmMatchStreaming(t *testing.T) {
	t.Parallel()

	payload := []byte("hello world")
	hmacKey := []byte("0123456789abcdef0123456789abcdef") // 32 bytes

	t.Run("default accepts header alg mismatching verification alg", func(t *testing.T) {
		t.Parallel()
		token := makeAlgConfusedDetachedCompact(t, "RS256", payload, hmacKey)

		_, err := jws.Verify(token,
			jws.WithKey(jwa.HS256(), hmacKey),
			jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
		)
		require.NoError(t, err, `streaming default verification should not compare header alg`)
	})

	t.Run("WithAlgorithmMatch(true) rejects header alg mismatching verification alg", func(t *testing.T) {
		t.Parallel()
		token := makeAlgConfusedDetachedCompact(t, "RS256", payload, hmacKey)

		_, err := jws.Verify(token,
			jws.WithKey(jwa.HS256(), hmacKey),
			jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
			jws.WithAlgorithmMatch(true),
		)
		require.Error(t, err, `streaming verification should reject alg mismatch`)
		require.ErrorIs(t, err, jws.VerifyError())
	})

	t.Run("matching alg verifies with WithAlgorithmMatch(true)", func(t *testing.T) {
		t.Parallel()
		signed, err := jws.Sign(nil,
			jws.WithKey(jwa.HS256(), hmacKey),
			jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
		)
		require.NoError(t, err, `streaming jws.Sign should succeed`)

		_, err = jws.Verify(signed,
			jws.WithKey(jwa.HS256(), hmacKey),
			jws.WithDetachedPayloadReader(bytes.NewReader(payload)),
			jws.WithAlgorithmMatch(true),
		)
		require.NoError(t, err, `streaming verify with matching alg should succeed`)
	})
}
