package jwe

import (
	"testing"

	"github.com/lestrrat/go-jwx/jwa"
	"github.com/stretchr/testify/assert"
)

func TestAesContentCipher(t *testing.T) {
	algs := []jwa.ContentEncryptionAlgorithm{
		jwa.A128GCM,
		jwa.A192GCM,
		jwa.A256GCM,
		jwa.A128CBC_HS256,
		jwa.A192CBC_HS384,
		jwa.A256CBC_HS512,
	}
	for _, alg := range algs {
		c, err := NewAesContentCipher(alg)
		if !assert.NoError(t, err, "BuildCipher for %s succeeds", alg) {
			return
		}
		t.Logf("keysize = %d", c.KeySize())
	}
}
