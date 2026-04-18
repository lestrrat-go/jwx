package jws

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"
)

// countingKeySink records every (alg, key) pair sunk by a KeyProvider
// so tests can assert on fan-out precisely.
type countingKeySink struct {
	pairs []algKeyPair
}

func (s *countingKeySink) Key(alg jwa.SignatureAlgorithm, key any) {
	s.pairs = append(s.pairs, algKeyPair{alg: alg, key: key})
}

// TestKeySetProviderFetchAllKeysAlgPrefilter asserts that when
// WithRequireKid(false) is used against a heterogeneous JWKS and the
// JWS protected header advertises an alg, keys whose type cannot
// produce that alg are skipped before reaching selectKey. This bounds
// verification fan-out and guards against CPU amplification on large
// multi-type JWKS.
func TestKeySetProviderFetchAllKeysAlgPrefilter(t *testing.T) {
	t.Parallel()

	rsaRaw, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaKey, err := jwk.Import(rsaRaw)
	require.NoError(t, err)

	ecRaw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecKey, err := jwk.Import(ecRaw)
	require.NoError(t, err)

	set := jwk.NewSet()
	require.NoError(t, set.AddKey(rsaKey))
	require.NoError(t, set.AddKey(ecKey))

	kp := &keySetProvider{
		set:            set,
		requireKid:     false,
		inferAlgorithm: true,
	}

	t.Run("alg=ES256 skips RSA key", func(t *testing.T) {
		t.Parallel()
		sig := NewSignature()
		hdr := NewHeaders()
		require.NoError(t, hdr.Set(AlgorithmKey, jwa.ES256()))
		sig.SetProtectedHeaders(hdr)

		sink := &countingKeySink{}
		require.NoError(t, kp.FetchKeys(context.Background(), sink, sig, &Message{}))
		require.Len(t, sink.pairs, 1, "only the EC key should be sunk")
		require.Equal(t, jwa.ES256(), sink.pairs[0].alg)
	})

	t.Run("alg=RS256 skips EC key", func(t *testing.T) {
		t.Parallel()
		sig := NewSignature()
		hdr := NewHeaders()
		require.NoError(t, hdr.Set(AlgorithmKey, jwa.RS256()))
		sig.SetProtectedHeaders(hdr)

		sink := &countingKeySink{}
		require.NoError(t, kp.FetchKeys(context.Background(), sink, sig, &Message{}))
		require.Len(t, sink.pairs, 1, "only the RSA key should be sunk")
		require.Equal(t, jwa.RS256(), sink.pairs[0].alg)
	})

	t.Run("no alg header still tries every key", func(t *testing.T) {
		t.Parallel()
		// Pre-existing opt-in behavior: without an alg in the header,
		// inferAlgorithm=true sinks every compatible alg for every key.
		// This test pins the documented fan-out so a future change is
		// an intentional decision.
		sig := NewSignature()
		sig.SetProtectedHeaders(NewHeaders())

		sink := &countingKeySink{}
		require.NoError(t, kp.FetchKeys(context.Background(), sink, sig, &Message{}))
		require.GreaterOrEqual(t, len(sink.pairs), 2, "both keys should be sunk when header has no alg")
	})
}
