package jwk_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v3/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"
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
		require.NoError(t, err, `key generation should succeed`)
		require.NoError(t, set.AddKey(k), `set.AddKey should succeed`)
		keys = append(keys, k)
	}

	require.Equal(t, set.Len(), 3, `set.Len should be 3`)

	for i, k := range keys {
		require.Equal(t, i, set.Index(k), `set.Index should return %d`, i)
	}

	for _, k := range keys {
		require.NoError(t, set.RemoveKey(k), `set.RemoveKey should succeed`)
	}

	require.Equal(t, set.Len(), 0, `set.Len should be 0`)

	for _, gen := range keygens {
		k, err := gen()
		require.NoError(t, err, `key generation should succeed`)
		require.NoError(t, set.AddKey(k), `set.Add should succeed`)
	}

	require.Equal(t, set.Len(), 3, `set.Len should be 3`)

	set.Clear()

	require.Equal(t, set.Len(), 0, `set.Len should be 0`)
}
