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

func TestKeyAlgorithmFrom(t *testing.T) {
	testcases := []struct {
		Input interface{}
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
