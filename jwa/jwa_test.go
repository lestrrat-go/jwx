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
