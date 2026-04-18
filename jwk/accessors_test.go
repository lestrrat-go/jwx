package jwk_test

import (
	"errors"
	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/require"
)

func TestGetTypedErrors(t *testing.T) {
	t.Parallel()

	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.KeyIDKey, "my-kid"))

	t.Run("missing field returns FieldNotFoundError", func(t *testing.T) {
		t.Parallel()
		_, err := jwk.Get[string](key, "nonexistent-field")
		require.Error(t, err)
		require.ErrorIs(t, err, jwk.FieldNotFoundError{}, `type check via errors.Is should match`)

		nf, ok := errors.AsType[jwk.FieldNotFoundError](err)
		require.True(t, ok, `errors.AsType should recover FieldNotFoundError`)
		require.Equal(t, "nonexistent-field", nf.Name)
	})

	t.Run("type mismatch returns FieldTypeMismatchError", func(t *testing.T) {
		t.Parallel()
		_, err := jwk.Get[int](key, jwk.KeyIDKey)
		require.Error(t, err)
		require.ErrorIs(t, err, jwk.FieldTypeMismatchError{})

		mm, ok := errors.AsType[jwk.FieldTypeMismatchError](err)
		require.True(t, ok, `errors.AsType should recover FieldTypeMismatchError`)
		require.Equal(t, jwk.KeyIDKey, mm.Name)
		require.IsType(t, "", mm.Got, `Got should be the stored string`)
		require.IsType(t, 0, mm.Want, `Want should be int zero`)
	})
}
