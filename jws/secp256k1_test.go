// +build jwx_es256k

package jws_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/internal/ecutil"
	"github.com/lestrrat-go/jwx/internal/jwxtest"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"
)

func TestES256K(t *testing.T) {
	if !ecutil.IsAvailable(jwa.Secp256k1) {
		t.SkipNow()
	}

	t.Parallel()
	key, err := jwxtest.GenerateEcdsaKey(jwa.Secp256k1)
	if !assert.NoError(t, err, "ECDSA key generated") {
		return
	}
	jwkKey, _ := jwk.New(key.PublicKey)
	keys := map[string]interface{}{
		"Verify(ecdsa.PublicKey)":  key.PublicKey,
		"Verify(*ecdsa.PublicKey)": &key.PublicKey,
		"Verify(jwk.Key)":          jwkKey,
	}
	testRoundtrip(t, payload, jwa.ES256K, key, keys)
}
