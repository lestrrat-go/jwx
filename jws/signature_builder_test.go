package jws_test

import (
	"crypto/sha256"
	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/require"
)

// fakeFastPathSigner is a no-op Signer used to exercise the precomputed
// {"alg":"..."} header fast path with an arbitrary algorithm name.
type fakeFastPathSigner struct{}

func (fakeFastPathSigner) Sign(_ any, payload []byte) ([]byte, error) {
	h := sha256.Sum256(payload)
	return h[:], nil
}

// A caller that registers a SignatureAlgorithm whose name contains
// JSON-special bytes must not be able to inject fields into the
// precomputed protected header. jws.WithKey caches a hand-built
// {"alg":"..."} literal; validation is deferred to jws.Sign so the
// option constructor stays error-free.
//
// Not parallel: each subtest mutates global state via
// jws.RegisterSigner / jwa.RegisterSignatureAlgorithm.
func TestSign_UnsafeAlgNameRejectedFastPath(t *testing.T) {
	testcases := []struct {
		name string
		alg  string
	}{
		{name: "injection via quote", alg: `ES256","x":"y`},
		{name: "backslash", alg: `RS\256`},
		{name: "control byte", alg: "RS\x01256"},
		{name: "non-ascii", alg: "RSβ256"},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			badAlg := jwa.NewSignatureAlgorithm(tc.alg)
			require.NoError(t, jws.RegisterSigner(badAlg, fakeFastPathSigner{}))
			t.Cleanup(func() {
				jws.UnregisterSigner(badAlg)
				jwa.UnregisterSignatureAlgorithm(badAlg)
			})

			_, err := jws.Sign([]byte("payload"), jws.WithKey(badAlg, nil))
			require.Error(t, err, "sign with unsafe alg name must fail")
			require.Contains(t, err.Error(), "alg")
		})
	}
}

// Sanity check: the happy path with a well-formed algorithm name
// still produces a valid JWS through the cached-header fast path.
func TestSign_SafeAlgNameFastPath(t *testing.T) {
	t.Parallel()

	priv, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)
	key, err := jwk.Import[jwk.Key](priv)
	require.NoError(t, err)

	signed, err := jws.Sign([]byte("payload"), jws.WithKey(jwa.RS256(), key))
	require.NoError(t, err)

	msg, err := jws.Parse(signed)
	require.NoError(t, err)
	sigs := msg.Signatures()
	require.Len(t, sigs, 1)
	gotAlg, ok := sigs[0].ProtectedHeaders().Algorithm()
	require.True(t, ok)
	require.Equal(t, jwa.RS256().String(), gotAlg.String())
}
