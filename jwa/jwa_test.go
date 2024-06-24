package jwa_test

import (
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/stretchr/testify/assert"
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
		Input interface{}
		Error bool
	}{
		{
			Input: jwa.RS256,
		},
		{
			Input: jwa.DIRECT,
		},
		{
			Input: jwa.A128CBC_HS256,
			Error: true,
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(fmt.Sprintf("%T", tc.Input), func(t *testing.T) {
			alg := jwa.KeyAlgorithmFrom(tc.Input)
			if tc.Error {
				if !assert.IsType(t, alg, jwa.InvalidKeyAlgorithm(""), `key should be invalid`) {
					return
				}
			} else {
				if !assert.Equal(t, alg, tc.Input, `key should be valid`) {
					return
				}
			}
		})
	}
}
