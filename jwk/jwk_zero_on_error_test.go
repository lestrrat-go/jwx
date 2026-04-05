package jwk_test

import (
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwk/jwkunsafe"
	"github.com/stretchr/testify/require"
)

// TestZeroPrivateKeyFieldsOnUnmarshalError verifies that when UnmarshalJSON
// fails mid-parse, any already-decoded private key material is zeroed before
// the error is returned. This prevents sensitive key bytes from lingering in
// memory after a failed parse.
func TestZeroPrivateKeyFieldsOnUnmarshalError(t *testing.T) {
	t.Parallel()

	t.Run("RSA", func(t *testing.T) {
		t.Parallel()

		// JSON with valid kty and d, but missing required fields n and e.
		// The d field will be decoded, then the required-field check will fail.
		src := `{"kty":"RSA","d":"AQAB"}`

		key, err := jwkunsafe.NewKey(jwa.RSA())
		require.NoError(t, err)

		err = json.Unmarshal([]byte(src), key)
		require.Error(t, err, "unmarshal should fail due to missing required fields")

		rsaKey, ok := key.(jwk.RSAPrivateKey)
		require.True(t, ok)

		d, exists := rsaKey.D()
		require.False(t, exists, "D() should report not-exists after failed unmarshal")
		require.Nil(t, d, "D() value should be nil after failed unmarshal")
	})

	t.Run("ECDSA", func(t *testing.T) {
		t.Parallel()

		// Has kty, crv, and d, but missing required fields x and y.
		src := `{"kty":"EC","crv":"P-256","d":"AQAB"}`

		key, err := jwkunsafe.NewKey(jwa.EC())
		require.NoError(t, err)

		err = json.Unmarshal([]byte(src), key)
		require.Error(t, err, "unmarshal should fail due to missing required fields")

		ecKey, ok := key.(jwk.ECDSAPrivateKey)
		require.True(t, ok)

		d, exists := ecKey.D()
		require.False(t, exists, "D() should report not-exists after failed unmarshal")
		require.Nil(t, d, "D() value should be nil after failed unmarshal")
	})

	t.Run("OKP", func(t *testing.T) {
		t.Parallel()

		// Has kty and d, but missing required fields crv and x.
		src := `{"kty":"OKP","d":"AQAB"}`

		key, err := jwkunsafe.NewKey(jwa.OKP())
		require.NoError(t, err)

		err = json.Unmarshal([]byte(src), key)
		require.Error(t, err, "unmarshal should fail due to missing required fields")

		okpKey, ok := key.(jwk.OKPPrivateKey)
		require.True(t, ok)

		d, exists := okpKey.D()
		require.False(t, exists, "D() should report not-exists after failed unmarshal")
		require.Nil(t, d, "D() value should be nil after failed unmarshal")
	})

	t.Run("Symmetric", func(t *testing.T) {
		t.Parallel()

		// Has kty and k (octets), but includes an unrecognized field that
		// will cause a decode error.
		src := `{"kty":"oct","k":"AQAB","bogus":!!!}`

		key, err := jwkunsafe.NewKey(jwa.OctetSeq())
		require.NoError(t, err)

		err = json.Unmarshal([]byte(src), key)
		require.Error(t, err, "unmarshal should fail due to malformed JSON")

		symKey, ok := key.(jwk.SymmetricKey)
		require.True(t, ok)

		octets, exists := symKey.Octets()
		require.False(t, exists, "Octets() should report not-exists after failed unmarshal")
		require.Nil(t, octets, "Octets() value should be nil after failed unmarshal")
	})
}
