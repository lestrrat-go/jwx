package jws_test

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/lestrrat-go/jwx/v4/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/require"
)

// TestVerifyWithKeySetContainingUnsupportedKey exercises jws.Verify
// against a JWK Set that mixes a usable RSA key with an UnsupportedKey
// placeholder (issue #2263). The valid key must still verify; a JWS
// whose kid points at the placeholder must fail with a descriptive
// error naming the kid, the raw kty, and the underlying reason.
func TestVerifyWithKeySetContainingUnsupportedKey(t *testing.T) {
	const payload = "Lorem ipsum"

	// The good key: sign with it and publish its public half under "goodkid".
	goodPriv, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err)
	require.NoError(t, goodPriv.Set(jwk.KeyIDKey, "goodkid"))
	signedGood, err := jws.Sign([]byte(payload), jws.WithKey(jwa.RS256(), goodPriv))
	require.NoError(t, err)

	goodPub, err := jwk.PublicKeyOf(goodPriv)
	require.NoError(t, err)
	require.NoError(t, goodPub.Set(jwk.AlgorithmKey, jwa.RS256()))
	goodPubJSON, err := json.Marshal(goodPub)
	require.NoError(t, err)

	// A JWS whose kid points at the placeholder entry.
	badPriv, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err)
	require.NoError(t, badPriv.Set(jwk.KeyIDKey, "badkid"))
	signedBad, err := jws.Sign([]byte(payload), jws.WithKey(jwa.RS256(), badPriv))
	require.NoError(t, err)

	unknownEntry := `{"kty":"FOO","use":"sig","kid":"badkid","x":"dGVzdA"}`
	setJSON := []byte(`{"keys":[` + unknownEntry + `,` + string(goodPubJSON) + `]}`)

	set, err := jwk.Parse(setJSON)
	require.NoError(t, err)
	require.Equal(t, 2, set.Len())

	t.Run("kid matches valid key verifies", func(t *testing.T) {
		got, err := jws.Verify(signedGood, jws.WithKeySet(set))
		require.NoError(t, err)
		require.Equal(t, payload, string(got))
	})

	t.Run("kid matches placeholder yields descriptive error", func(t *testing.T) {
		_, err := jws.Verify(signedBad, jws.WithKeySet(set))
		require.Error(t, err)
		require.Contains(t, err.Error(), "badkid")
		require.Contains(t, err.Error(), "FOO")
		require.Contains(t, err.Error(), "unsupported key type")
	})

	t.Run("placeholder rejection is reported when kid is not required", func(t *testing.T) {
		// Set contains only the placeholder. On the try-all-keys path
		// (WithRequireKid(false)) the alg-based key-type prefilter must
		// not silently swallow the placeholder: the error must still
		// name the kid, the raw kty, and the retained parse reason.
		phSet, err := jwk.Parse([]byte(`{"keys":[` + unknownEntry + `]}`))
		require.NoError(t, err)
		require.Equal(t, 1, phSet.Len())

		_, err = jws.Verify(signedBad, jws.WithKeySet(phSet, jws.WithRequireKid(false)))
		require.Error(t, err)
		require.Contains(t, err.Error(), "badkid")
		require.Contains(t, err.Error(), "FOO")
		require.Contains(t, err.Error(), "unsupported key type")
	})
}

// TestUnsupportedKeyRejectionNotMaskedBySkippedKeys pins the try-all-keys
// path (WithRequireKid(false)) against a mixed set: an unsupported-key
// placeholder plus a supported key that emits no verification candidate
// (no "alg" member, algorithm inference disabled). The skipped supported
// key must not mask the placeholder's named rejection in the final error.
func TestUnsupportedKeyRejectionNotMaskedBySkippedKeys(t *testing.T) {
	const payload = "Lorem ipsum"

	ecPriv, err := jwxtest.GenerateEcdsaJwk()
	require.NoError(t, err)
	require.NoError(t, ecPriv.Set(jwk.KeyIDKey, "eckey"))
	signed, err := jws.Sign([]byte(payload), jws.WithKey(jwa.ES256(), ecPriv))
	require.NoError(t, err)

	// The supported key: correct EC public key, but with NO "alg" member,
	// so selectKey has nothing to emit while inference is off.
	ecPub, err := jwk.PublicKeyOf(ecPriv)
	require.NoError(t, err)
	ecPubJSON, err := json.Marshal(ecPub)
	require.NoError(t, err)

	corruptEntry := `{"kty":"RSA","kid":"badrsa","n":"!!!not-base64!!!","e":"AQAB"}`
	setJSON := []byte(`{"keys":[` + corruptEntry + `,` + string(ecPubJSON) + `]}`)
	set, err := jwk.Parse(setJSON)
	require.NoError(t, err)
	require.Equal(t, 2, set.Len())

	_, err = jws.Verify(signed, jws.WithKeySet(set, jws.WithRequireKid(false)))
	require.Error(t, err)
	require.Contains(t, err.Error(), "badrsa", `the placeholder's kid must be named`)
	require.Contains(t, err.Error(), "RSA", `the placeholder's raw kty must be named`)
	require.Contains(t, err.Error(), "unsupported key type", `the placeholder's named rejection must not be discarded`)
}

// captureSignerVerifier is a custom Signer/Verifier pair that records
// whether its callbacks were invoked. Verify always succeeds, so if a
// placeholder ever leaks through to it, the enclosing test fails loudly
// (jws.Verify would return no error).
type captureSignerVerifier struct {
	signCalled   *bool
	verifyCalled *bool
}

func (sv captureSignerVerifier) Sign(_ any, payload []byte) ([]byte, error) {
	*sv.signCalled = true
	h := sha256.Sum256(payload)
	return h[:], nil
}

func (sv captureSignerVerifier) Verify(_ any, _, _ []byte) error {
	*sv.verifyCalled = true
	return nil
}

// TestUnsupportedKeyNeverReachesCustomSignerVerifier pins the
// crypto-isolation invariant for custom-registered algorithms: an
// UnsupportedKey placeholder must be rejected before any Signer or
// Verifier callback receives it as key material, whether it arrives via
// jws.WithKey or via a custom KeyProvider.
func TestUnsupportedKeyNeverReachesCustomSignerVerifier(t *testing.T) {
	// Note: registration has global effect; don't run in parallel.
	customAlg := jwa.NewSignatureAlgorithm("UnsupportedKeyTest256")
	var signCalled, verifyCalled bool
	sv := captureSignerVerifier{signCalled: &signCalled, verifyCalled: &verifyCalled}
	require.NoError(t, jws.RegisterSigner(customAlg, sv))
	require.NoError(t, jws.RegisterVerifier(customAlg, sv))
	t.Cleanup(func() {
		jws.UnregisterSigner(customAlg)
		jws.UnregisterVerifier(customAlg)
		jwa.UnregisterSignatureAlgorithm(customAlg)
	})

	// A placeholder whose kty probes as RSA — the shape that previously
	// slipped past key classification when a custom Signer/Verifier was
	// registered for the algorithm.
	corruptEntry := `{"kty":"RSA","kid":"hostile","n":"!!!not-base64!!!","e":"AQAB"}`
	set, err := jwk.Parse([]byte(`{"keys":[` + corruptEntry + `]}`))
	require.NoError(t, err)
	placeholder, ok := set.Key(0)
	require.True(t, ok)
	require.True(t, jwk.IsUnsupportedKey(placeholder))

	t.Run("Sign with WithKey rejects the placeholder", func(t *testing.T) {
		_, err := jws.Sign([]byte("payload"), jws.WithKey(customAlg, placeholder))
		require.Error(t, err)
		require.Contains(t, err.Error(), "hostile")
		require.Contains(t, err.Error(), "RSA")
		require.Contains(t, err.Error(), "unsupported key type")
		require.False(t, signCalled, `the custom Signer must never receive the placeholder`)
	})

	// A well-formed message under the custom algorithm, for the verify
	// paths below (the custom signer accepts a nil key).
	signed, err := jws.Sign([]byte("payload"), jws.WithKey(customAlg, nil))
	require.NoError(t, err)
	signCalled = false

	t.Run("Verify with WithKey rejects the placeholder", func(t *testing.T) {
		_, err := jws.Verify(signed, jws.WithKey(customAlg, placeholder))
		require.Error(t, err)
		require.Contains(t, err.Error(), "hostile")
		require.Contains(t, err.Error(), "RSA")
		require.Contains(t, err.Error(), "unsupported key type")
		require.False(t, verifyCalled, `the custom Verifier must never receive the placeholder`)
	})

	t.Run("Verify with a custom KeyProvider rejects the placeholder", func(t *testing.T) {
		provider := jws.KeyProviderFunc(func(_ context.Context, sink jws.KeySink, _ *jws.Signature, _ *jws.Message) error {
			sink.Key(customAlg, placeholder)
			return nil
		})
		_, err := jws.Verify(signed, jws.WithKeyProvider(provider))
		require.Error(t, err)
		require.Contains(t, err.Error(), "hostile")
		require.Contains(t, err.Error(), "RSA")
		require.Contains(t, err.Error(), "unsupported key type")
		require.False(t, verifyCalled, `the custom Verifier must never receive the placeholder`)
	})
}
