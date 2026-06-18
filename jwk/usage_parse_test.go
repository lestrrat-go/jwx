package jwk_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/require"
)

func TestKeyUsageValidationAtParse(t *testing.T) {
	// strictKeyUsage is a process-global toggle. Ensure it is restored to its
	// default (strict on) after each subtest that mutates it.
	restoreStrict := func(t *testing.T) {
		t.Helper()
		require.NoError(t, jwk.Settings(jwk.WithStrictKeyUsage(true)))
	}

	t.Run("invalid use rejected by default (symmetric)", func(t *testing.T) {
		_, err := jwk.ParseKey([]byte(`{"kty":"oct","k":"AQ","use":"admin"}`))
		require.Error(t, err, `parsing an unregistered "use" value should fail by default`)
	})

	t.Run("invalid use rejected by default (RSA)", func(t *testing.T) {
		const src = `{"kty":"RSA","n":"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H5UAqAn3MJA1pCe7d7-Ut2K46_5g","e":"AQAB","use":"admin"}`
		_, err := jwk.ParseKey([]byte(src))
		require.Error(t, err, `parsing an unregistered "use" value should fail by default`)
	})

	t.Run("invalid use accepted when strict disabled", func(t *testing.T) {
		require.NoError(t, jwk.Settings(jwk.WithStrictKeyUsage(false)))
		defer restoreStrict(t)

		key, err := jwk.ParseKey([]byte(`{"kty":"oct","k":"AQ","use":"admin"}`))
		require.NoError(t, err, `parsing should succeed when strict key usage is disabled`)
		usage, ok := key.KeyUsage()
		require.True(t, ok)
		require.Equal(t, "admin", usage)
	})

	t.Run("valid use accepted by default", func(t *testing.T) {
		key, err := jwk.ParseKey([]byte(`{"kty":"oct","k":"AQ","use":"sig"}`))
		require.NoError(t, err, `parsing a registered "use" value should succeed`)
		usage, ok := key.KeyUsage()
		require.True(t, ok)
		require.Equal(t, "sig", usage)
	})
}
