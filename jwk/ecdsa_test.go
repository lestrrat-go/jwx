package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/lestrrat/go-jwx/jwa"
	"github.com/stretchr/testify/assert"
)

func TestParse_EcdsaPrivateKey(t *testing.T) {
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
	set, err := ParseString(s)
	if !assert.NoError(t, err, "Parsing private key is successful") {
		return
	}

	ecdsakey, ok := set.Keys[0].(*EcdsaPrivateKey)
	if !assert.True(t, ok, "Type assertion for EcdsaPrivateKey is successful") {
		return
	}

	var privkey *ecdsa.PrivateKey
	var pubkey *ecdsa.PublicKey

	{
		mkey, err := ecdsakey.EcdsaPublicKey.Materialize()
		if !assert.NoError(t, err, "EcdsaPublickKey.Materialize is successful") {
			return
		}
		var ok bool
		pubkey, ok = mkey.(*ecdsa.PublicKey)
		if !assert.True(t, ok, "Materialized key is a *ecdsa.PublicKey") {
			return
		}
	}

	if !assert.Equal(t, elliptic.P256(), pubkey.Curve, "Curve matches") {
		return
	}

	if !assert.NotEmpty(t, pubkey.X, "N exists") {
		return
	}

	if !assert.NotEmpty(t, pubkey.Y, "E exists") {
		return
	}

	{
		mkey, err := ecdsakey.Materialize()
		if !assert.NoError(t, err, "EcdsaPrivateKey.Materialize is successful") {
			return
		}
		var ok bool
		privkey, ok = mkey.(*ecdsa.PrivateKey)
		if !assert.True(t, ok, "Materialized key is a *ecdsa.PrivateKey") {
			return
		}
	}

	if !assert.NotEmpty(t, privkey.D, "D exists") {
		return
	}

	if !assert.NotPanics(t, func() {
		NewEcdsaPrivateKey(privkey)
	}, "NewEcdsaPrivateKey does not panic") {
		return
	}

	if !assert.NotPanics(t, func() {
		NewEcdsaPublicKey(&privkey.PublicKey)
	}, "NewEcdsaPublicKey does not panic") {
		return
	}
}

func TestParse_EcdsaInitKey(t *testing.T) {
	// Generate an ECDSA P-256 test key.
	ecPrk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if !assert.NoError(t, err, "Failed to generate EC P-256 key") {
		return
	}
	// Test initialization of a private EC JWK.
	prk := NewEcdsaPrivateKey(ecPrk)
	err = prk.Set("kid", "MyKey")
	assert.NoError(t, err, "Set private key ID success")
	assert.Equal(t, prk.KeyType, jwa.EC, "Private key type match")
	assert.Equal(t, prk.Curve, jwa.P256, "Private key curve match")
	assert.Equal(t, prk.X.Bytes(), ecPrk.X.Bytes(), "Private key X match")
	assert.Equal(t, prk.Y.Bytes(), ecPrk.Y.Bytes(), "Private key Y match")
	assert.Equal(t, prk.D.Bytes(), ecPrk.D.Bytes(), "Private key D match")
	assert.Equal(t, prk.KeyID, "MyKey", "Private key ID match")

	// Test initialization of a public EC JWK.
	puk := NewEcdsaPublicKey(&ecPrk.PublicKey)
	err = puk.Set("kid", "MyKey")
	assert.NoError(t, err, " Set public key ID success")
	assert.Equal(t, puk.KeyType, jwa.EC, "Public key type match")
	assert.Equal(t, puk.Curve, jwa.P256, "Public key curve match")
	assert.Equal(t, puk.X.Bytes(), ecPrk.X.Bytes(), "Public key X match")
	assert.Equal(t, puk.Y.Bytes(), ecPrk.Y.Bytes(), "Public key Y march")
	assert.Equal(t, prk.KeyID, "MyKey", "Public key ID match")
}
