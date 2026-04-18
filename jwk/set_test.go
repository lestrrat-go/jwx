package jwk_test

import (
	"sort"
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

// fakeStructKey embeds jwk.Key to satisfy the interface without implementing
// any methods. AddKey never calls methods on its argument, so a nil-embedded
// stub is enough to exercise the reflect-guard code path for struct-valued
// Key implementations.
type fakeStructKey struct {
	jwk.Key
}

func TestSetAddKeyNil(t *testing.T) {
	t.Run("typed-nil interface", func(t *testing.T) {
		var k jwk.Key
		require.Error(t, jwk.NewSet().AddKey(k), `AddKey should return an error for nil Key, not panic`)
	})
	t.Run("nil concrete pointer", func(t *testing.T) {
		var k *fakeStructKey
		require.Error(t, jwk.NewSet().AddKey(k), `AddKey should return an error for nil pointer Key, not panic`)
	})
	t.Run("struct-value Key", func(t *testing.T) {
		require.NotPanics(t, func() {
			_ = jwk.NewSet().AddKey(fakeStructKey{})
		}, `AddKey must not panic when Key's dynamic type is a struct`)
	})
}

func TestSetKeys(t *testing.T) {
	set := jwk.NewSet()
	require.NoError(t, set.Set("a", "foo"), `Set should succeed`)
	require.NoError(t, set.Set("b", "bar"), `Set should succeed`)

	keys := set.Keys()
	sort.Strings(keys) // sorting is necessary because the order of keys obtained from a regular map is not guaranteed
	require.EqualValues(t, []string{"a", "b"}, keys, `Keys should return "a" and "b"`)
}
