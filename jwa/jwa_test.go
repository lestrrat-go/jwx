package jwa_test

import (
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/stretchr/testify/require"
)

func TestSanity(t *testing.T) {
	var k1 jwa.KeyAlgorithm = jwa.RS256()
	_, ok := k1.(jwa.SignatureAlgorithm)
	require.True(t, ok, `converting k1 to jws.SignatureAlgorithm should succeed`)
	_, ok = k1.(jwa.KeyEncryptionAlgorithm)
	require.False(t, ok, `converting k1 to jws.KeyEncryptionAlgorithm should fail`)

	var k2 jwa.KeyAlgorithm = jwa.DIRECT()
	_, ok = k2.(jwa.SignatureAlgorithm)
	require.False(t, ok, `converting k2 to jws.SignatureAlgorithm should fail`)
	_, ok = k2.(jwa.KeyEncryptionAlgorithm)
	require.True(t, ok, `converting k2 to jws.KeyEncryptionAlgorithm should succeed`)
}

func TestRFC9864(t *testing.T) {
	t.Parallel()

	t.Run("EdDSA is deprecated", func(t *testing.T) {
		t.Parallel()
		require.True(t, jwa.EdDSA().IsDeprecated(), `EdDSA should be deprecated`)
	})
	t.Run("EdDSAEd25519 is not deprecated", func(t *testing.T) {
		t.Parallel()
		require.False(t, jwa.EdDSAEd25519().IsDeprecated(), `EdDSAEd25519 should not be deprecated`)
	})
	// EdDSAEd448 tests moved to ext/ed448
	t.Run("EdDSAEd25519 string value", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "Ed25519", jwa.EdDSAEd25519().String(), `EdDSAEd25519 should have string value Ed25519`)
	})
	t.Run("LookupSignatureAlgorithm for Ed25519", func(t *testing.T) {
		t.Parallel()
		v, ok := jwa.LookupSignatureAlgorithm("Ed25519")
		require.True(t, ok, `LookupSignatureAlgorithm("Ed25519") should succeed`)
		require.Equal(t, jwa.EdDSAEd25519(), v)
	})
	t.Run("LookupEllipticCurveAlgorithm for Ed25519 still works", func(t *testing.T) {
		t.Parallel()
		v, ok := jwa.LookupEllipticCurveAlgorithm("Ed25519")
		require.True(t, ok, `LookupEllipticCurveAlgorithm("Ed25519") should still succeed`)
		require.Equal(t, jwa.Ed25519(), v)
	})
}

func TestKeyAlgorithmFrom(t *testing.T) {
	testcases := []struct {
		Input any
		Error bool
	}{
		{
			Input: jwa.RS256(),
		},
		{
			Input: jwa.DIRECT(),
		},
		{
			Input: jwa.A128CBC_HS256(),
		},
		{
			Input: "dummy",
			Error: true,
		},
	}

	for _, tc := range testcases {
		t.Run(fmt.Sprintf("%T", tc.Input), func(t *testing.T) {
			alg, err := jwa.KeyAlgorithmFrom(tc.Input)
			if tc.Error {
				require.Error(t, err, `creating key alrgorithm should fail`)
			} else {
				require.NoError(t, err, `creating key alrgorithm should succeed`)
				require.Equal(t, alg, tc.Input, `key should be valid`)
			}
		})
	}
}
