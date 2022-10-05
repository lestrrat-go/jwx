package jwa_test

import (
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stringer struct {
	src string
}

func (s stringer) String() string {
	return s.src
}

func TestSanity(t *testing.T) {
	var k1 jwa.KeyAlgorithm = jwa.RS256
	if _, ok := k1.(jwa.SignatureAlgorithm); !assert.True(t, ok, `converting k1 to jws.SignatureAlgorithm should succeed`) {
		return
	}
	if _, ok := k1.(jwa.KeyEncryptionAlgorithm); !assert.False(t, ok, `converting k1 to jws.KeyEncryptionAlgorithm should fail`) {
		return
	}
	var k2 jwa.KeyAlgorithm = jwa.DIRECT
	if _, ok := k2.(jwa.SignatureAlgorithm); !assert.False(t, ok, `converting k2 to jws.SignatureAlgorithm should fail`) {
		return
	}
	if _, ok := k2.(jwa.KeyEncryptionAlgorithm); !assert.True(t, ok, `converting k2 to jws.KeyEncryptionAlgorithm should succeed`) {
		return
	}
}

func TestKeyAlgorithmFrom(t *testing.T) {
	testcases := []struct {
		Input     interface{}
		IsUnknown bool
		Error     bool
	}{
		{
			Input: jwa.RS256,
		},
		{
			Input: jwa.DIRECT,
		},
		{
			Input: jwa.A128CBC_HS256,
		},
		{
			Input:     "my-awesome-algorithm",
			IsUnknown: true,
		},
		{
			Input: 1.1,
			Error: true,
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(fmt.Sprintf("%T", tc.Input), func(t *testing.T) {
			alg, err := jwa.KeyAlgorithmFrom(tc.Input)
			if tc.Error {
				require.Error(t, err, `trying to convert value %#v should be an error`, tc.Input)
				return
			}

			if tc.IsUnknown {
				require.IsType(t, alg, jwa.UnknownKeyAlgorithm(""), `key should be unknown`)
				return
			}

			require.Equal(t, alg, tc.Input)
		})
	}
}
