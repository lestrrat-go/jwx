//go:build jwx_es256k
// +build jwx_es256k

package jws_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v2/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
)

func init() {
	hasES256K = true
}

func TestES256K(t *testing.T) {
	payload := []byte("Hello, World!")

	t.Parallel()
	key, err := jwxtest.GenerateEcdsaKey(jwa.Secp256k1)
	if !assert.NoError(t, err, "ECDSA key generated") {
		return
	}
	jwkKey, _ := jwk.FromRaw(key.PublicKey)
	keys := map[string]interface{}{
		"Verify(ecdsa.PublicKey)":  key.PublicKey,
		"Verify(*ecdsa.PublicKey)": &key.PublicKey,
		"Verify(jwk.Key)":          jwkKey,
	}
	testRoundtrip(t, payload, jwa.ES256K, key, keys)
}
