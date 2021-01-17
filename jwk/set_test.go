package jwk_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/internal/jwxtest"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"
)

func TestSet(t *testing.T) {
	set := jwk.NewSet()

	keygens := []func() (jwk.Key, error){
		jwxtest.GenerateRsaJwk,
		jwxtest.GenerateEcdsaJwk,
		jwxtest.GenerateSymmetricJwk,
	}

	//nolint:prealloc
	var keys []jwk.Key
	for _, gen := range keygens {
		k, err := gen()
		if !assert.NoError(t, err, `key generation should succeed`) {
			return
		}
		if !assert.True(t, set.Add(k), `set.Add should succeed`) {
			return
		}
		keys = append(keys, k)
	}

	if !assert.Equal(t, set.Len(), 3, `set.Len should be 3`) {
		return
	}

	for i, k := range keys {
		if !assert.Equal(t, i, set.Index(k), `set.Index should return %d`, i) {
			return
		}
	}

	for _, k := range keys {
		if !assert.True(t, set.Remove(k), `set.Remove should succeed`) {
			return
		}
	}

	if !assert.Equal(t, set.Len(), 0, `set.Len should be 0`) {
		return
	}

	for _, gen := range keygens {
		k, err := gen()
		if !assert.NoError(t, err, `key generation should succeed`) {
			return
		}
		if !assert.True(t, set.Add(k), `set.Add should succeed`) {
			return
		}
	}

	if !assert.Equal(t, set.Len(), 3, `set.Len should be 3`) {
		return
	}

	set.Clear()

	if !assert.Equal(t, set.Len(), 0, `set.Len should be 0`) {
		return
	}
}
