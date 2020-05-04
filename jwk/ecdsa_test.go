package jwk_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"
)

func TestECDSA(t *testing.T) {
	t.Run("Parse Private Key", func(t *testing.T) {
		const s = `{"keys":
       [
         {"kty":"EC",
          "crv":"P-256",
          "key_ops": ["verify"],
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

		if _, ok := set.Keys[0].(jwk.ECDSAPrivateKey); !assert.True(t, ok, `should be jwk.ECDSAPrivateKey`) {
			return
		}

		var rawPrivKey ecdsa.PrivateKey
		privKey := set.Keys[0].(jwk.ECDSAPrivateKey)
		if !assert.NoError(t, privKey.Raw(&rawPrivKey), "Raw should succeed") {
			return
		}

		if !assert.IsType(t, ecdsa.PrivateKey{}, rawPrivKey, `should be *ecdsa.PrivateKey`) {
			return
		}

		pubkey, err := privKey.PublicKey()
		if !assert.NoError(t, err, "Should be able to get ECDSA public key") {
			return
		}

		var rawPubKey ecdsa.PublicKey
		if !assert.NoError(t, pubkey.Raw(&rawPubKey), "Raw should succeed") {
			return
		}

		if !assert.IsType(t, ecdsa.PublicKey{}, rawPubKey, `should be *ecdsa.PublicKey`) {
			return
		}

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

		if !assert.NoError(t, puk.Set(jwk.KeyIDKey, "MyKey"), " Set public key ID success") {
			return
		}

		if !assert.Equal(t, puk.KeyType(), jwa.EC, "Public key type match") {
			return
		}

		if !assert.Equal(t, prk.KeyID(), "MyKey", "Public key ID match") {
			return
		}
	})
	t.Run("Marshall Unmarshal Public Key", func(t *testing.T) {
		s := `{"keys":
       [
         {"kty":"EC",
          "crv":"P-256",
          "key_ops": ["verify"],
          "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
          "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
          "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
				 }
       ]
  }`
		expectedPublicKey := `{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}`

		var set jwk.Set
		if !assert.NoError(t, json.Unmarshal([]byte(s), &set), "unmarshal(set) should be successful") {
			return
		}

		if _, ok := set.Keys[0].(jwk.ECDSAPrivateKey); !assert.True(t, ok, "first key should be ECDSAPrivateKey") {
			return
		}
		key := set.Keys[0].(jwk.ECDSAPrivateKey)

		var rawKey ecdsa.PrivateKey
		if !assert.NoError(t, key.Raw(&rawKey), `materialize should succeed`) {
			return
		}

		if !assert.Equal(t, jwa.P256, key.Crv(), `curve name should match`) {
			return
		}

		pubKey, err := key.PublicKey()
		if !assert.NoError(t, err, `should PublicKey succeed`) {
			return
		}

		var rawPubKey ecdsa.PublicKey
		if !assert.NoError(t, pubKey.Raw(&rawPubKey), `public key should succeed`) {
			return
		}

		ECDSAPublicKey, err := jwk.New(rawPubKey)
		if !assert.NoError(t, err, `jwk.New with *rsa.PublicKey should succeed`) {
			return
		}

		// verify marshal
		pubKeyBytes, err := json.Marshal(ECDSAPublicKey)
		if !assert.NoError(t, err, `marshaling ECDSA public key should succeed`) {
			return
		}

		if !assert.Equal(t, expectedPublicKey, string(pubKeyBytes), `generated JSON key should match`) {
			return
		}

		// verify unmarshal
		ECDSAPublicKey2, err := jwk.ParseKey([]byte(expectedPublicKey))
		if !assert.NoError(t, err, `json.Unmarshal should succeed for ECDSA public key`) {
			return
		}
		pECDSAPublicKey := ECDSAPublicKey.(jwk.ECDSAPublicKey)
		if !assert.Equal(t, pECDSAPublicKey, ECDSAPublicKey2, "public keys should match") {
			return
		}
	})
	t.Run("Marshall Unmarshal Private Key", func(t *testing.T) {
		s := `{"keys":
       [
         {"kty":"EC",
          "crv":"P-256",
          "key_ops": ["verify"],
          "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
          "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
          "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
				 }
       ]
  }`
		expectedPrivKey := `{"kty":"EC","crv":"P-256","d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE","key_ops":["verify"],"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}`

		set, err := jwk.ParseString(s)
		if err != nil {
			t.Fatal("Failed to parse JWK ECDSA")
		}
		ECDSAPrivateKey := set.Keys[0].(jwk.ECDSAPrivateKey)

		privKeyBytes, err := json.Marshal(ECDSAPrivateKey)
		if err != nil {
			t.Fatal("Failed to marshal ECDSAPrivateKey")
		}
		// verify marshal

		if !assert.Equal(t, expectedPrivKey, string(privKeyBytes), `should match`) {
			t.Logf("%s", privKeyBytes)
			t.Logf("%s", expectedPrivKey)
			return
		}

		// verify unmarshal

		expECDSAPrivateKey, err := jwk.ParseKey([]byte(expectedPrivKey))
		if !assert.NoError(t, err, `jwk.ParseKey should succeed`) {
			return
		}

		if !assert.Equal(t, expECDSAPrivateKey, ECDSAPrivateKey, "ECDSAPrivate keys should match") {
			return
		}
	})
}
