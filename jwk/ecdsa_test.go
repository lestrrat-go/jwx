package jwk_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"
)

func TestECDSA(t *testing.T) {
	t.Run("Parse Private Key", func(t *testing.T) {
		s := `{"keys":
       [
         {"kty":"EC",
          "crv":"P-256",
          "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
          "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
          "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
				 }
       ]
  }`
		set, err := jwk.ParseString(s)
		if !assert.NoError(t, err, "Parsing private key is successful") {
			return
		}

		if !assert.Len(t, set.Keys, 1, `should be 1 key`) {
			return
		}

		rawKey, err := set.Keys[0].Materialize()
		if !assert.NoError(t, err, "Materialize should succeed") {
			return
		}

		if !assert.IsType(t, &ecdsa.PrivateKey{}, rawKey, `should be *ecdsa.PrivateKey`) {
			return
		}

		rawPrivKey := rawKey.(*ecdsa.PrivateKey)

		pubkey, err := set.Keys[0].(*jwk.ECDSAPrivateKey).PublicKey()
		if !assert.NoError(t, err, "Should be able to get ECDSA public key") {
			return
		}

		rawKey, err = pubkey.Materialize()
		if !assert.NoError(t, err, "Materialize should succeed") {
			return
		}

		if !assert.IsType(t, &ecdsa.PublicKey{}, rawKey, `should be *ecdsa.PublicKey`) {
			return
		}

		rawPubKey := rawKey.(*ecdsa.PublicKey)

		if !assert.Equal(t, elliptic.P256(), rawPubKey.Curve, "Curve matches") {
			return
		}

		if !assert.NotEmpty(t, rawPubKey.X, "X exists") {
			return
		}

		if !assert.NotEmpty(t, rawPubKey.Y, "Y exists") {
			return
		}

		if !assert.NotEmpty(t, rawPrivKey.D, "D exists") {
			return
		}
	})
	t.Run("Initialization", func(t *testing.T) {
		// Generate an ECDSA P-256 test key.
		ecPrk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if !assert.NoError(t, err, "Failed to generate EC P-256 key") {
			return
		}
		// Test initialization of a private EC JWK.
		prk, err := jwk.New(ecPrk)
		if !assert.NoError(t, err, `jwk.New should succeed`) {
			return
		}

		if !assert.NoError(t, prk.Set(jwk.KeyIDKey, "MyKey"), "Set private key ID success") {
			return
		}

		if !assert.Equal(t, prk.KeyType(), jwa.EC, "Private key type match") {
			return
		}

		if !assert.Equal(t, prk.KeyID(), "MyKey", "Private key ID match") {
			return
		}

		// Test initialization of a public EC JWK.
		puk, err := jwk.New(&ecPrk.PublicKey)
		if !assert.NoError(t, err, `jwk.New should succeed`) {
			return
		}

		if ! assert.NoError(t, puk.Set(jwk.KeyIDKey, "MyKey"), " Set public key ID success") {
			return
		}

		if !assert.Equal(t, puk.KeyType(), jwa.EC, "Public key type match") {
			return
		}

		if !assert.Equal(t, prk.KeyID(), "MyKey", "Public key ID match") {
			return
		}
	})
}
