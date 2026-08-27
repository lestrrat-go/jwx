//go:build jwx_es256k

package jws_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v3/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/stretchr/testify/require"
)

func init() {
	hasES256K = true
}

func TestES256K(t *testing.T) {
	payload := []byte("Hello, World!")

	t.Parallel()
	key, err := jwxtest.GenerateEcdsaKey(jwa.Secp256k1())
	require.NoError(t, err, "ECDSA key generated")
	jwkKey, _ := jwk.Import(key.PublicKey)
	keys := map[string]any{
		"Verify(ecdsa.PublicKey)":  key.PublicKey,
		"Verify(*ecdsa.PublicKey)": &key.PublicKey,
		"Verify(jwk.Key)":          jwkKey,
	}
	testRoundtrip(t, payload, jwa.ES256K(), key, keys)
}

// TestES256KUnaffectedByStrictECDSA pins that jws.WithStrictECDSA(true)
// leaves extension algorithms on their own curves alone. The check keys its
// table on the three built-in dsig ECDSA algorithm names
// (ECDSAWithP256AndSHA256 and friends); ES256K maps to
// dsigsecp256k1.ECDSAWithSecp256k1AndSHA256, which is not one of them, so
// the lookup must miss and a secp256k1 key must keep signing successfully
// under ES256K.
func TestES256KUnaffectedByStrictECDSA(t *testing.T) {
	t.Parallel()

	key, err := jwxtest.GenerateEcdsaKey(jwa.Secp256k1())
	require.NoError(t, err, "ECDSA key generated")

	_, err = jws.Sign([]byte("hello"), jws.WithKey(jwa.ES256K(), key), jws.WithStrictECDSA(true))
	require.NoError(t, err, "ES256K signing must not be rejected by the ECDSA curve-binding check")
}
