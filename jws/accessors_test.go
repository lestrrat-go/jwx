package jws_test

import (
	"errors"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/require"
)

func TestGetTypedErrors(t *testing.T) {
	t.Parallel()

	hdr := jws.NewHeaders()
	require.NoError(t, hdr.Set(jws.KeyIDKey, "my-kid"))

	t.Run("missing field returns FieldNotFoundError", func(t *testing.T) {
		t.Parallel()
		_, err := jws.Get[string](hdr, "nonexistent-field")
		require.Error(t, err)
		require.ErrorIs(t, err, jws.FieldNotFoundError{})

		nf, ok := errors.AsType[jws.FieldNotFoundError](err)
		require.True(t, ok)
		require.Equal(t, "nonexistent-field", nf.Name)
	})

	t.Run("type mismatch returns FieldTypeMismatchError", func(t *testing.T) {
		t.Parallel()
		_, err := jws.Get[int](hdr, jws.KeyIDKey)
		require.Error(t, err)
		require.ErrorIs(t, err, jws.FieldTypeMismatchError{})

		mm, ok := errors.AsType[jws.FieldTypeMismatchError](err)
		require.True(t, ok)
		require.Equal(t, jws.KeyIDKey, mm.Name)
	})
}
