package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"math/big"
	"strconv"
	"testing"

	"github.com/lestrrat/go-jwx/buffer"
	"github.com/lestrrat/go-jwx/jwa"
	"github.com/stretchr/testify/assert"
)

func TestJwksSerializationPadding(t *testing.T) {
	x := new(big.Int)
	y := new(big.Int)

	e := &EssentialHeader{}
	e.KeyType = jwa.EC
	x.SetString("123520477547912006148785171019615806128401248503564636913311359802381551887648525354374204836279603443398171853465", 10)
	y.SetString("13515585925570416130130241699780319456178918334914981404162640338265336278264431930522217750520011829472589865088261", 10)
	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P384(),
		X:     x,
		Y:     y,
	}
	jwkPubKey := NewEcdsaPublicKey(pubKey)
	jwkPubKey.EssentialHeader = e
	jwkJSON, err := json.Marshal(jwkPubKey)
	if !assert.NoError(t, err, "JWK Marshalled") {
		return
	}

	_, err = Parse(jwkJSON)
	if !assert.NoError(t, err, "JWK Parsed") {
		return
	}

}

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

func TestAppendix_B(t *testing.T) {
	var jwksrc = []byte(`{"keys":
       [
        {"kty":"RSA",
         "use":"sig",
         "kid":"1b94c",
         "n":"vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08PLbK_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Qu2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4aYWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwHMTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-meMvVfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ",
         "e":"AQAB",
         "x5c": ["MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA=="]}
       ]
     }`)

	set, err := Parse(jwksrc)
	if !assert.NoError(t, err, "Parse should succeed") {
		return
	}
	if !assert.Len(t, set.Keys, 1, "There should be 1 key") {
		return
	}

	{
		key, ok := set.Keys[0].(*RsaPublicKey)
		if !assert.True(t, ok, "set.Keys[0] should be a RsaPublicKey") {
			return
		}
		if !assert.Len(t, key.X509CertChain, 1, "key.X509CertChain should be 1 cert") {
			return
		}
	}
}

func TestConstructEssentialHeader(t *testing.T) {
	var jwksrc = []byte(`{"keys":
       [
        {"kty":"oct",
         "use":"sig",
         "key_ops": ["sign","verify"],
         "alg": "HS256",
         "k":"test",
         "kid":"test"}
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
		ops, err := key.Get("key_ops")
		if !assert.NoError(t, err, "key.Get(key_ops) should succeed") {
			return
		}
		if !assert.Equal(t, ops, []KeyOperation{KeyOpSign, KeyOpVerify}, "key.KeyOps should be equal") {
			return
		}
	}
}
