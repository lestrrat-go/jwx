package jwe_test

import (
	"errors"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwe"
	"github.com/stretchr/testify/require"
)

func TestGetTypedErrors(t *testing.T) {
	t.Parallel()

	hdr := jwe.NewHeaders()
	require.NoError(t, hdr.Set(jwe.KeyIDKey, "my-kid"))

	t.Run("missing field returns FieldNotFoundError", func(t *testing.T) {
		t.Parallel()
		_, err := jwe.Get[string](hdr, "nonexistent-field")
		require.Error(t, err)
		require.ErrorIs(t, err, jwe.FieldNotFoundError{})

		nf, ok := errors.AsType[jwe.FieldNotFoundError](err)
		require.True(t, ok)
		require.Equal(t, "nonexistent-field", nf.Name)
	})

	t.Run("type mismatch returns FieldTypeMismatchError", func(t *testing.T) {
		t.Parallel()
		_, err := jwe.Get[int](hdr, jwe.KeyIDKey)
		require.Error(t, err)
		require.ErrorIs(t, err, jwe.FieldTypeMismatchError{})

		mm, ok := errors.AsType[jwe.FieldTypeMismatchError](err)
		require.True(t, ok)
		require.Equal(t, jwe.KeyIDKey, mm.Name)
	})
}
