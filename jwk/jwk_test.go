package jwk

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/lestrrat/go-jwx/buffer"
	"github.com/lestrrat/go-jwx/jwa"
	"github.com/stretchr/testify/assert"
)

func TestJwksRoundtrip(t *testing.T) {
	ks1 := &Set{}
	for _, use := range []string{"enc", "sig"} {
		for i := 0; i < 2; i++ {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if !assert.NoError(t, err, "RSA key generated") {
				return
			}

			k, err := NewRsaPrivateKey(key)
			if !assert.NoError(t, err, "JWK RSA key generated") {
				return
			}

			k.KeyUsage = use
			k.KeyID = use + strconv.Itoa(i)

			ks1.Keys = append(ks1.Keys, k)
		}
	}

	buf, err := json.MarshalIndent(ks1, "", "  ")
	if !assert.NoError(t, err, "JSON marshal succeeded") {
		return
	}

	ks2, err := Parse(buf)
	if !assert.NoError(t, err, "JSON unmarshal succeeded") {
		return
	}

	for _, use := range []string{"enc", "sig"} {
		for i := 0; i < 2; i++ {
			kid := use + strconv.Itoa(i)
			keys := ks2.LookupKeyID(kid)
			if !assert.Len(t, keys, 1, "Should be 1 key") {
				return
			}
			key1 := keys[0]

			pk1, ok := key1.(*RsaPrivateKey)
			if !assert.True(t, ok, "Should be RsaPrivateKey") {
				return
			}

			keys = ks1.LookupKeyID(kid)
			if !assert.Len(t, keys, 1, "Should be 1 key") {
				return
			}

			key2 := keys[0]
			pk2, ok := key2.(*RsaPrivateKey)
			if !assert.True(t, ok, "Should be RsaPrivateKey") {
				return
			}

			if !assert.Equal(t, pk1, pk2, "Keys should match (kid = %s)", kid) {
				return
			}
		}
	}
}

func TestRsaPrivateKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if !assert.NoError(t, err, "RSA key generated") {
		return
	}

	k1, err := NewRsaPrivateKey(key)
	if !assert.NoError(t, err, "JWK RSA key generated") {
		return
	}

	jsonbuf, err := json.MarshalIndent(k1, "", "  ")
	if !assert.NoError(t, err, "Marshal to JSON succeeded") {
		return
	}

	t.Logf("%s", jsonbuf)

	k2 := &RsaPrivateKey{}
	if !assert.NoError(t, json.Unmarshal(jsonbuf, k2), "Unmarshal from JSON succeeded") {
		return
	}

	if !assert.Equal(t, k1, k2, "keys match") {
		return
	}

	k3, err := Parse(jsonbuf)
	if !assert.NoError(t, err, "Parse should succeed") {
		return
	}

	if !assert.Equal(t, k1, k3.Keys[0], "keys match") {
		return
	}
}

func TestAppendix_A1(t *testing.T) {
	var jwksrc = []byte(`{"keys":
       [
         {"kty":"EC",
          "crv":"P-256",
          "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
          "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
          "use":"enc",
          "kid":"1"},

         {"kty":"RSA",
          "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
          "e":"AQAB",
          "alg":"RS256",
          "kid":"2011-04-29"}
       ]
     }`)

	set, err := Parse(jwksrc)
	if !assert.NoError(t, err, "Parse should succeed") {
		return
	}

	if !assert.Len(t, set.Keys, 2, "There should be 2 keys") {
		return
	}

	{
		key, ok := set.Keys[0].(*EcdsaPublicKey)
		if !assert.True(t, ok, "set.Keys[0] should be a EcdsaPublicKey") {
			return
		}

		if !assert.Equal(t, jwa.P256, key.Curve, "curve is P-256") {
			return
		}
	}
}

func TestAppendix_A3(t *testing.T) {
	var jwksrc = []byte(`{"keys":
       [
         {"kty":"oct",
          "alg":"A128KW",
          "k":"GawgguFyGrWKav7AX4VKUg"},

         {"kty":"oct",
          "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
          "kid":"HMAC key used in JWS spec Appendix A.1 example"}
       ]
     }`)
	set, err := Parse(jwksrc)
	if !assert.NoError(t, err, "Parse should succeed") {
		return
	}

	{
		key, ok := set.Keys[0].(*SymmetricKey)
		if !assert.True(t, ok, "set.Keys[0] should be a SymmetricKey") {
			return
		}

		bkey, err := buffer.FromBase64([]byte("GawgguFyGrWKav7AX4VKUg"))
		if !assert.NoError(t, err, "created key to compare") {
			return
		}

		ckey, err := key.Materialize()
		if !assert.NoError(t, err, "materialized key") {
			return
		}

		if !assert.Equal(t, jwa.OctetSeq, key.KeyType, "key type matches") ||
			!assert.Equal(t, jwa.A128KW.String(), key.Algorithm, "key algorithm matches") ||
			!assert.Equal(t, bkey.Bytes(), ckey, "key content matches") {
			return
		}
	}
}