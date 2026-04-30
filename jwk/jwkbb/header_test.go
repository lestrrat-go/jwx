package jwkbb_test

import (
	"errors"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwk/jwkbb"
	"github.com/stretchr/testify/require"
)

func TestHeader(t *testing.T) {
	t.Parallel()

	t.Run("HeaderHas/HeaderGetString on JWKS", func(t *testing.T) {
		t.Parallel()
		h := jwkbb.HeaderParse([]byte(`{"keys":[],"renewal_kid":"foo"}`))
		require.True(t, jwkbb.HeaderHas(h, "keys"), `keys should exist`)
		require.True(t, jwkbb.HeaderHas(h, "renewal_kid"), `renewal_kid should exist`)
		require.False(t, jwkbb.HeaderHas(h, "missing"), `missing should not exist`)

		v, err := jwkbb.HeaderGetString(h, "renewal_kid")
		require.NoError(t, err)
		require.Equal(t, "foo", v)

		_, err = jwkbb.HeaderGetString(h, "missing")
		require.ErrorIs(t, err, jwkbb.ErrHeaderNotFound())
	})

	t.Run("HeaderHas on bare JWK", func(t *testing.T) {
		t.Parallel()
		h := jwkbb.HeaderParse([]byte(`{"kty":"oct","k":"AAAA"}`))
		require.False(t, jwkbb.HeaderHas(h, "keys"), `bare JWK should not have keys`)
		require.True(t, jwkbb.HeaderHas(h, "kty"))
	})

	t.Run("parse error deferred", func(t *testing.T) {
		t.Parallel()
		h := jwkbb.HeaderParse([]byte(`{not json`))
		require.False(t, jwkbb.HeaderHas(h, "anything"), `parse error should surface as not-found`)

		_, err := jwkbb.HeaderGetString(h, "anything")
		require.Error(t, err)
		require.False(t, errors.Is(err, jwkbb.ErrHeaderNotFound()), `parse error is not a not-found error`)
	})

	t.Run("HeaderGetStringBytes aliases", func(t *testing.T) {
		t.Parallel()
		h := jwkbb.HeaderParse([]byte(`{"kty":"RSA"}`))
		b, err := jwkbb.HeaderGetStringBytes(h, "kty")
		require.NoError(t, err)
		require.Equal(t, []byte("RSA"), b)
	})
}
