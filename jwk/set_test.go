package jwk_test

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/require"
)

func TestSet(t *testing.T) {
	set := jwk.NewSet()

	keygens := []func() (jwk.Key, error){
		jwxtest.GenerateRsaJwk,
		func() (jwk.Key, error) { return jwxtest.GenerateEcdsaJwk(jwa.P256()) },
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

// A blocked iterator must fail the test without hanging the whole test suite.
func runSetIteration(t *testing.T, iterate func() error) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- iterate() }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("set mutation inside the iterator deadlocked")
	}
}

func TestSetAllAllowsMutation(t *testing.T) {
	set := jwk.NewSet()
	keys := make([]jwk.Key, 0, 3)
	for _, value := range []string{"first", "second", "third"} {
		key, err := jwk.Import[jwk.Key]([]byte(value))
		require.NoError(t, err)
		require.NoError(t, set.AddKey(key))
		keys = append(keys, key)
	}
	var got []jwk.Key
	var indices []int
	runSetIteration(t, func() error {
		for i, key := range set.All() {
			indices = append(indices, i)
			got = append(got, key)
			if err := set.RemoveKey(key); err != nil {
				return err
			}
		}
		return nil
	})
	require.Equal(t, []int{0, 1, 2}, indices)
	require.Equal(t, keys, got, "iteration must retain the original keys and indices")
	require.Zero(t, set.Len())
}

func TestSetFieldsAllowsMutation(t *testing.T) {
	set := jwk.NewSet()
	want := map[string]any{"first": 1, "second": 2, "third": 3}
	for name, value := range want {
		require.NoError(t, set.Set(name, value))
	}
	got := make(map[string]any)
	runSetIteration(t, func() error {
		for name, value := range set.Fields() {
			got[name] = value
			if err := set.Remove(name); err != nil {
				return err
			}
			if err := set.Set("added", 4); err != nil {
				return err
			}
		}
		return nil
	})
	require.Equal(t, want, got, "new fields must not enter an active iteration")
	require.Equal(t, map[string]any{"added": 4}, maps.Collect(set.Fields()))
}

func TestSetIteratorsSnapshotAtEachIteration(t *testing.T) {
	set := jwk.NewSet()
	all, fields := set.All(), set.Fields()
	key, err := jwk.Import[jwk.Key]([]byte("key"))
	require.NoError(t, err)
	require.NoError(t, set.AddKey(key))
	require.NoError(t, set.Set("field", "value"))
	runSetIteration(t, func() error {
		var seenKey bool
		for i, got := range all {
			if i != 0 || got != key {
				return fmt.Errorf("unexpected key at index %d", i)
			}
			seenKey = true
			if err := set.Clear(); err != nil {
				return err
			}
			break
		}
		if !seenKey {
			return fmt.Errorf("iterator missed the key added before iteration")
		}
		for range all {
			return fmt.Errorf("reused iterator retained a removed key")
		}
		if err := set.Set("new", "value"); err != nil {
			return err
		}
		var seenField bool
		for name := range fields {
			if name != "new" {
				return fmt.Errorf("unexpected field %q", name)
			}
			if err := set.Remove(name); err != nil {
				return err
			}
			seenField = true
			break
		}
		if !seenField {
			return fmt.Errorf("iterator missed the field added before iteration")
		}
		for range fields {
			return fmt.Errorf("reused iterator retained a removed field")
		}
		return nil
	})
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

// jwk.Parse is documented to accept a single bare JWK and return a Set
// containing that one key. The streaming UnmarshalJSON pushes every
// non-"keys" top-level field into privateParams (the slot for JWKS-level
// extension members), then re-parses the whole blob as a Key when no
// "keys" field was seen. If privateParams is not cleared on that fallback
// path, the same key fields end up serialized at both the JWKS top level
// and inside keys[0] on the next MarshalJSON.
func TestSetSingleKeyRoundTripDoesNotDuplicateFields(t *testing.T) {
	src, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err, `GenerateRsaJwk should succeed`)

	input, err := json.Marshal(src)
	require.NoError(t, err, `marshaling the source key should succeed`)

	set, err := jwk.Parse(input)
	require.NoError(t, err, `Parse should accept a single bare JWK`)
	require.Equal(t, 1, set.Len(), `Set should contain exactly one key`)

	out, err := json.Marshal(set)
	require.NoError(t, err, `marshaling the Set should succeed`)

	var top map[string]any
	require.NoError(t, json.Unmarshal(out, &top), `unmarshal into map should succeed`)
	require.Equal(t, []string{"keys"}, mapKeysSorted(top),
		`top level should be a JWKS with exactly the "keys" field; got duplicated fields: %s`, string(out))
}

func mapKeysSorted(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func TestSetKeys(t *testing.T) {
	set := jwk.NewSet()
	require.NoError(t, set.Set("a", "foo"), `Set should succeed`)
	require.NoError(t, set.Set("b", "bar"), `Set should succeed`)

	keys := set.Keys()
	slices.Sort(keys) // sorting is necessary because the order of keys obtained from a regular map is not guaranteed
	require.EqualValues(t, []string{"a", "b"}, keys, `Keys should return "a" and "b"`)
}
