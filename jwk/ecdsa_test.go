package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"testing"

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
