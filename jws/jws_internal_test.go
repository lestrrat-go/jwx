package jws

import (
	"sync"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws/legacy"
	"github.com/stretchr/testify/require"
)

func wipeoutLegacySignatureRegistry() {
	enableLegacySignersOnce = &sync.Once{}
	signerDB = make(map[jwa.SignatureAlgorithm]SignerFactory)
}

func TestLegacySignatureSign(t *testing.T) {
	// This tests using the legacy NewSigner API, WHICH SHOULD NOT BE USED ANYMORE.
	// This test just ensures that the legacy API still works for those who, for some
	// reason, decided to use this API.
	t.Run("Test GH#1459", func(t *testing.T) {
		// For this test, we need to do something naughty, which is to wipe out the
		// legacy signature algorithm registry to make sure NewSigner works out
		// of the box. This is why the test is in `jws` package, not `jws_test`.
		wipeoutLegacySignatureRegistry()
		require.Len(t, signerDB, 0, "signerDB should be empty")

		// Test all supported signature algorithms using NewSigner. Note that NewSigner
		// is a deprecated API. When the right time comes, we should remove this test.
		for _, sig := range jwa.SignatureAlgorithms() {
			if sig == jwa.NoSignature() {
				// Skip alg=none
				continue
			}
			if sig == jwa.EdDSAEd448() {
				// Ed448 uses circl via a separate module
				// (github.com/lestrrat-go/jwx-circl-ed448),
				// not the legacy signer path.
				continue
			}
			signer, err := NewSigner(sig)
			require.NoError(t, err, "NewSigner should succeed")
			require.NotNil(t, signer, "NewSigner should return a valid signer")
		}
		require.NotEqual(t, len(signerDB), 0, "signerDB should not be empty anymore")
	})
	t.Run("use legacy signature algorithm registraiton API", func(t *testing.T) {
		// Create a custom algorithm "HS256-legacy" for testing
		hs256LegacyAlg := jwa.NewSignatureAlgorithm("HS256-legacy")

		// Register the legacy HS256 signer factory
		err := RegisterSigner(hs256LegacyAlg, SignerFactoryFn(func() (Signer, error) {
			return legacy.NewHMACSigner(jwa.HS256()), nil
		}))
		require.NoError(t, err, "RegisterSigner should succeed")

		// Clean up after test
		t.Cleanup(func() {
			UnregisterSigner(hs256LegacyAlg)
			jwa.UnregisterSignatureAlgorithm(hs256LegacyAlg)
		})

		// Test data
		key := []byte("test-secret-key-for-legacy-comparison")
		payload := []byte("test payload for legacy signature comparison")

		// Create a signed JWS using Sign with HS256 algorithm
		signed, err := Sign(payload, WithKey(jwa.HS256(), key))
		require.NoError(t, err, "Sign should succeed")

		// Parse the JWS to extract the signature
		msg, err := Parse(signed)
		require.NoError(t, err, "Parse should succeed")
		require.Len(t, msg.Signatures(), 1, "should have one signature")

		jwsSignature := msg.Signatures()[0].Signature()

		// Create a signature using Signature.Sign() with HS256-legacy algorithm
		sig := NewSignature()
		legacySigner, err := NewSigner(hs256LegacyAlg)
		require.NoError(t, err, "NewSigner should succeed for legacy algorithm")

		rawSig, _, err := sig.Sign(payload, legacySigner, key)
		require.NoError(t, err, "Signature.Sign should succeed")

		// Compare the signatures - they should be identical
		require.Equal(t, jwsSignature, rawSig, "signatures from Sign and Signature.Sign should be identical")
	})
}
