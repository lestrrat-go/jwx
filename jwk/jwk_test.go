package jwk_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/lestrrat-go/jwx/internal/base64"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	k, err := jwk.New(nil)
	if !assert.Nil(t, k, "key should be nil") {
		return
	}
	if !assert.Error(t, err, "nil key should cause an error") {
		return
	}
}

func TestParse(t *testing.T) {
	verify := func(t *testing.T, src string, expected interface{}) {
		t.Helper()
		t.Run("json.Unmarshal", func(t *testing.T) {
			var set jwk.Set
			if err := json.Unmarshal([]byte(src), &set); !assert.NoError(t, err, `json.Unmarshal should succeed`) {
				return
			}

			if !assert.True(t, len(set.Keys) > 0, "set.Keys should be greater than 0") {
				return
			}
			for _, key := range set.Keys {
				if !assert.IsType(t, expected, key, "key should be a jwk.RSAPublicKey") {
					return
				}
			}
		})
		t.Run("jwk.Parse", func(t *testing.T) {
			t.Helper()
			set, err := jwk.ParseBytes([]byte(`{"keys":[` + src + `]}`))
			if !assert.NoError(t, err, `jwk.Parse should succeed`) {
				return
			}

			if !assert.True(t, set.Len() > 0, "set.Len should be greater than 0") {
				return
			}

			for iter := set.Iterate(context.TODO()); iter.Next(context.TODO()); {
				pair := iter.Pair()
				key := pair.Value.(jwk.Key)

				switch key := key.(type) {
				case *jwk.RSAPrivateKey, *jwk.ECDSAPrivateKey, *jwk.RSAPublicKey, *jwk.ECDSAPublicKey, *jwk.SymmetricKey:
				default:
					assert.Fail(t, fmt.Sprintf("invalid type: %T", key))
				}
			}
		})
	}

	t.Run("RSA Public Key", func(t *testing.T) {
		const src = `{
      "e":"AQAB",
			"kty":"RSA",
      "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
		}`
		verify(t, src, &jwk.RSAPublicKey{})
	})
	t.Run("RSA Private Key", func(t *testing.T) {
		const src = `{
      "kty":"RSA",
      "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
      "e":"AQAB",
      "d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
      "p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
      "q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
      "dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
      "dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
      "qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
      "alg":"RS256",
      "kid":"2011-04-29"
     }`
		verify(t, src, &jwk.RSAPrivateKey{})
	})
	t.Run("ECDSA Private Key", func(t *testing.T) {
		const src = `{
		  "kty" : "EC",
		  "crv" : "P-256",
		  "x"   : "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
		  "y"   : "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI",
		  "d"   : "0g5vAEKzugrXaRbgKG0Tj2qJ5lMP4Bezds1_sTybkfk"
		}`
		verify(t, src, &jwk.ECDSAPrivateKey{})
	})
	t.Run("Invalid ECDSA Private Key", func(t *testing.T) {
		const src = `{
		  "kty" : "EC",
		  "crv" : "P-256",
		  "y"   : "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI",
		  "d"   : "0g5vAEKzugrXaRbgKG0Tj2qJ5lMP4Bezds1_sTybkfk"
		}`
		_, err := jwk.ParseString(src)
		if !assert.Error(t, err, `jwk.ParseString should fail`) {
			return
		}
	})
}

func TestRoundtrip(t *testing.T) {
	generateRSA := func(use string, keyID string) (jwk.Key, error) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, errors.Wrap(err, `failed to generate RSA private key`)
		}

		k, err := jwk.New(key)
		if err != nil {
			return nil, errors.Wrap(err, `failed to generate jwk.RSAPrivateKey`)
		}

		k.Set(jwk.KeyUsageKey, use)
		k.Set(jwk.KeyIDKey, keyID)
		return k, nil
	}

	generateECDSA := func(use, keyID string) (jwk.Key, error) {
		key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return nil, errors.Wrap(err, `failed to generate ECDSA private key`)
		}

		k, err := jwk.New(key)
		if err != nil {
			return nil, errors.Wrap(err, `failed to generate jwk.ECDSAPrivateKey`)
		}

		k.Set(jwk.KeyUsageKey, use)
		k.Set(jwk.KeyIDKey, keyID)
		return k, nil
	}

	generateSymmetric := func(use, keyID string) (jwk.Key, error) {
		sharedKey := make([]byte, 64)
		rand.Read(sharedKey)

		key, err := jwk.New(sharedKey)
		if err != nil {
			return nil, errors.Wrap(err, `failed to generate jwk.SymmetricKey`)
		}

		key.Set(jwk.KeyUsageKey, use)
		key.Set(jwk.KeyIDKey, keyID)
		return key, nil
	}

	tests := []struct {
		use      string
		keyID    string
		generate func(string, string) (jwk.Key, error)
	}{
		{
			use:      "enc",
			keyID:    "enc1",
			generate: generateRSA,
		},
		{
			use:      "enc",
			keyID:    "enc2",
			generate: generateRSA,
		},
		{
			use:      "sig",
			keyID:    "sig1",
			generate: generateRSA,
		},
		{
			use:      "sig",
			keyID:    "sig2",
			generate: generateRSA,
		},
		{
			use:      "sig",
			keyID:    "sig3",
			generate: generateSymmetric,
		},
		{
			use:      "enc",
			keyID:    "enc4",
			generate: generateECDSA,
		},
		{
			use:      "enc",
			keyID:    "enc5",
			generate: generateECDSA,
		},
		{
			use:      "sig",
			keyID:    "sig4",
			generate: generateECDSA,
		},
		{
			use:      "sig",
			keyID:    "sig5",
			generate: generateECDSA,
		},
	}

	var ks1 jwk.Set
	for _, tc := range tests {
		key, err := tc.generate(tc.use, tc.keyID)
		if !assert.NoError(t, err, `tc.generate should succeed`) {
			return
		}
		ks1.Keys = append(ks1.Keys, key)
	}

	buf, err := json.MarshalIndent(ks1, "", "  ")
	if !assert.NoError(t, err, "JSON marshal succeeded") {
		return
	}

	ks2, err := jwk.ParseBytes(buf)
	if !assert.NoError(t, err, "JSON unmarshal succeeded") {
		t.Logf("%s", buf)
		return
	}

	for _, tc := range tests {
		keys := ks2.LookupKeyID(tc.keyID)
		if !assert.Len(t, keys, 1, "Should be 1 key") {
			return
		}
		key1 := keys[0]

		keys = ks1.LookupKeyID(tc.keyID)
		if !assert.Len(t, keys, 1, "Should be 1 key") {
			return
		}

		key2 := keys[0]

		pk1json, _ := json.Marshal(key1)
		pk2json, _ := json.Marshal(key2)
		if !assert.Equal(t, pk1json, pk2json, "Keys should match (kid = %s)", tc.keyID) {
			return
		}
	}
}

/*

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

func TestRSAPrivateKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if !assert.NoError(t, err, "RSA key generated") {
		return
	}

	k1, err := NewRSAPrivateKey(key)
	if !assert.NoError(t, err, "JWK RSA key generated") {
		return
	}

	jsonbuf, err := json.MarshalIndent(k1, "", "  ")
	if !assert.NoError(t, err, "Marshal to JSON succeeded") {
		return
	}

	t.Logf("%s", jsonbuf)

	k2 := &RSAPrivateKey{}
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
*/

func TestAppendix(t *testing.T) {
	t.Run("A1", func(t *testing.T) {
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

		set, err := jwk.ParseBytes(jwksrc)
		if !assert.NoError(t, err, "Parse should succeed") {
			return
		}

		if !assert.Equal(t, set.Len(), 2, "There should be 2 keys") {
			return
		}

		{
			key, ok := set.Keys[0].(*jwk.ECDSAPublicKey)
			if !assert.True(t, ok, "set.Keys[0] should be a EcdsaPublicKey") {
				return
			}

			var rawkey ecdsa.PublicKey
			if !assert.NoError(t, key.Materialize(&rawkey), `materialize should succeed`) {
				return
			}

			if !assert.Equal(t, jwa.P256, key.Curve(), "curve is P-256") {
				return
			}
		}
	})

	t.Run("A3", func(t *testing.T) {
		const (
			key1 = `GawgguFyGrWKav7AX4VKUg`
			key2 = `AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow`
		)

		buf1, err := base64.DecodeString(key1)
		if !assert.NoError(t, err, "failed to decode key1") {
			return
		}

		buf2, err := base64.DecodeString(key2)
		if !assert.NoError(t, err, "failed to decode key2") {
			return
		}

		var jwksrc = []byte(`{"keys":
       [
         {"kty":"oct",
          "alg":"A128KW",
          "k":"` + key1 + `"},

         {"kty":"oct",
          "k":"` + key2 + `",
          "kid":"HMAC key used in JWS spec Appendix A.1 example"}
       ]
     }`)

		var set jwk.Set
		if !assert.NoError(t, json.Unmarshal(jwksrc, &set), "jwk.Set unmarshal should succeed") {
			return
		}

		tests := []struct {
			headers map[string]interface{}
			key     []byte
		}{
			{
				headers: map[string]interface{}{
					jwk.KeyTypeKey:   jwa.OctetSeq,
					jwk.AlgorithmKey: jwa.A128KW.String(),
				},
				key: buf1,
			},
			{
				headers: map[string]interface{}{
					jwk.KeyTypeKey: jwa.OctetSeq,
					jwk.KeyIDKey:   "HMAC key used in JWS spec Appendix A.1 example",
				},
				key: buf2,
			},
		}

		for i, data := range tests {
			key, ok := set.Keys[i].(*jwk.SymmetricKey)
			if !assert.True(t, ok, "set.Keys[%d] should be a SymmetricKey", i) {
				return
			}

			var ckey []byte
			if !assert.NoError(t, key.Materialize(&ckey), "materialized key") {
				return
			}

			if !assert.Equal(t, data.key, ckey, `key byte sequence should match`) {
				return
			}

			for k, expected := range data.headers {
				k := k
				expected := expected
				t.Run(k, func(t *testing.T) {
					if v, ok := key.Get(k); assert.True(t, ok, "getting %s from %T should succeed", k, key) {
						if !assert.Equal(t, expected, v, "value for %s should match", k) {
							return
						}
					}
				})
			}
		}
	})
	t.Run("B", func(t *testing.T) {
		var jwksrc = []byte(`{"keys":
	          [
	           {"kty":"RSA",
	            "use":"sig",
	            "kid":"1b94c",
	            "n":"vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08PLbK_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Qu2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4aYWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwHMTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-meMvVfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ",
	            "e":"AQAB",
	            "x5c": [
								"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"
	          ]
	        }]}`)

		set, err := jwk.ParseBytes(jwksrc)
		if !assert.NoError(t, err, "Parse should succeed") {
			return
		}
		if !assert.Len(t, set.Keys, 1, "There should be 1 key") {
			return
		}

		{
			key, ok := set.Keys[0].(*jwk.RSAPublicKey)
			if !assert.True(t, ok, "set.Keys[0] should be a jwk.RSAPublicKey") {
				return
			}
			if !assert.Len(t, key.X509CertChain(), 3, "key.X509CertChain should be 3 cert") {
				return
			}
		}
	})
}

func TestFetch(t *testing.T) {
	const jwksrc = `{"keys":
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
	        }`

	verify := func(t *testing.T, set *jwk.Set) {
		key, ok := set.Keys[0].(*jwk.ECDSAPublicKey)
		if !assert.True(t, ok, "set.Keys[0] should be a EcdsaPublicKey") {
			return
		}

		var rawkey ecdsa.PublicKey
		if !assert.NoError(t, key.Materialize(&rawkey), "materialize should succeed") {
			return
		}

		if !assert.Equal(t, jwa.P256, key.Curve(), "curve is P-256") {
			return
		}
	}
	t.Run("HTTP", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/":
				w.WriteHeader(http.StatusOK)
				io.WriteString(w, jwksrc)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()

		cl := srv.Client()

		set, err := jwk.Fetch(srv.URL, jwk.WithHTTPClient(cl))
		if !assert.NoError(t, err, `failed to fetch jwk`) {
			return
		}
		verify(t, set)
	})
	t.Run("Local File", func(t *testing.T) {
		f, err := ioutil.TempFile("", "jwk-fetch-test")
		if !assert.NoError(t, err, `failed to generate temporary file`) {
			return
		}
		defer f.Close()
		defer os.Remove(f.Name())

		io.WriteString(f, jwksrc)
		f.Sync()

		set, err := jwk.Fetch("file://" + f.Name())
		if !assert.NoError(t, err, `failed to fetch jwk`) {
			return
		}
		verify(t, set)
	})
	t.Run("Invalid Scheme", func(t *testing.T) {
		set, err := jwk.Fetch("gopher://foo/bar")
		if !assert.Nil(t, set, `set should be nil`) {
			return
		}
		if !assert.Error(t, err, `invalid sche,e should be an error`) {
			return
		}
	})
}

func TestGitHubIssue136(t *testing.T) {
	// JWK key from https://cognito-identity.amazonaws.com/.well-known/jwks_uri
	// as of Feb 25 2020
	const src = `{"keys":[
{"kty":"RSA","alg":"RS512","use":"sig","kid":"ap-northeast-11","n":"AI7mc1assO5n6yB4b7jPCFgVLYPSnwt4qp2BhJVAmlXRntRZ5w4910oKNZDOr4fe/BWOI2Z7upUTE/ICXdqirEkjiPbBN/duVy5YcHsQ5+GrxQ/UbytNVN/NsFhdG8W31lsE4dnrGds5cSshLaohyU/aChgaIMbmtU0NSWQ+jwrW8q1PTvnThVQbpte59a0dAwLeOCfrx6kVvs0Y7fX7NXBbFxe8yL+JR3SMJvxBFuYC+/om5EIRIlRexjWpNu7gJnaFFwbxCBNwFHahcg5gdtSkCHJy8Gj78rsgrkEbgoHk29pk8jUzo/O/GuSDGw8qXb6w0R1+UsXPYACOXM8C8+E=","e":"AQAB"},
{"kty":"RSA","alg":"RS512","use":"sig","kid":"ap-northeast-21","n":"AIHzdsSdHLX/a2jBt9GjpX1cvnWmeKhKgA3Pa2d5lTWMuQlWqP8yRnMDvH4j8yrzkf3uTSUVtfHYUDwYvXTjQMKyw1DYprrCo6g0aKThVmCvgfGCL2nWSiAcql6qnAUMhvvyTLZkPCLGgJnqUxuwkxYzs+hoXrNx2WKUyNOVIGXEVCxJBXJaWe4ERrk9iiu022UPmZuQwsHvf010eH7tHhw03MZJ9lTVpC+A+rSgGuWUo8Nb3d8OcBf3ObjL4gQ9EeclhXSt7TUnXR0NxHnErGiDAE6FGePRbAFoAJWoSsM4FoqixGr6E0uTsA5IfJ+VnveYCTpqsuxYy/lupZNxwRE=","e":"AQAB"},
{"kty":"RSA","alg":"RS512","use":"sig","kid":"ap-south-11","n":"AIgVHiyTeMG5uNWFBR5lombNayt53U0nWpBFWTUsv2Wey9O2hsUVnAZGlcziy6g9X7E/EDS+itQ084tIeFs7hfvDgJd/GiT4nxt34wTxu59c4Lw8XmrDQD6YaPu0BocWoWN/ukh6yBjJSG3iUv2fVNaG+HeYr0dRmw1hmUhX3RQkjmgJMh6UZetjsw11VgxOeVqS9vTbyVZQhIFMEYZh9upyLFVSwsb6PaSwv0I5+RNaIUjiFmSC1dwzkoRcldluXMOuf+Rb+7/y9tMqHFy2WBvruhuUUDmT7+BFuhujl/IyUmelbNrWLdSGXEsCJf11OvBtocv3zCnS04DefXNJY8M=","e":"AQAB"},
{"kty":"RSA","alg":"RS512","use":"sig","kid":"ap-southeast-11","n":"AIjiMJhloeH+hIzx/hpgny9zFWy+dpu03F3fXoijkq7iohjbzxqmF1iAsrx12v7I1VENN72VoALEHBIvF807fmclwF5+7R3EjzMyP/SJgEWYKecCBlk23QKGBTmDvm22/X76IIUEdlMHC/Rm88iDGchQV0Hw6jtTOJMyIuhqL/foGrJLOuwq2Jhbg6o3GZDWY8JRkRCCKV+yJZLpDLtnBG8fM2Z0bDmGJHbnHyyFDmoqAWbeSZKS2K+LnHoqd+wbQaYpTnX2fVq2AEiz+I6RD+tvWegG5Lgw5xnuST9R9d3Xp++mIg8YsSoD8agtVwOh6qxkYnq4vEEGaU8Qsm+BeNs=","e":"AQAB"},
{"kty":"RSA","alg":"RS512","use":"sig","kid":"ap-southeast-22","n":"AJZzNUBnF1H6rFFiqJbiziWW7VVbyoXWH7CTUMOYzJo/7WsyJkPt95z7iLvTPR26TWg2oQIKd5Di/B5qRuPq3sg0LyEwM9QCRNyJ3be9rLSOkLCFAtwwxgonpJkMSpFwmrlrxcXQMF0xyz9IXPRgrI9KlCG0Xd/BQnV79zeMDObwMZXzj8ki1Xuh06R5XGvacNds72H5oByjeoNYzhMktqVO8pWlNKbRATyPi/HwdG8DhNH5G4TPXiBMwNhp3W/lK4JhMMgbJ01y5Xq/32ib1qSxp8ec1LKkoJdbiWxWkpXLPUahEN38+J1NeVAH+Nv8ZMqoV9n2IGIts0UJY8a0ZWc=","e":"AQAB"},
{"kty":"RSA","alg":"RS512","use":"sig","kid":"ca-central-11","n":"AOj6hiK7+Xc95sDrRxq6+DIj7votGhbsLZUuOAd4leTB390jTcL1JfK77WzPi8MtaeTiGNyykdQ0HJ/qHfBoAPUPh/yhn0vXC3d7vkAn6YM0vtc9hfdMXm47yaUeIR3QIu8qwLhHzTu1q2O1QqzYYT2dftg4X55f3TZNg88GE9HIj83V/xa+8bg4gRlFHYglb6jXANh08R8goBjxjMFWg7SS5V48L5GaqYef7/RszpXIMxyYriOq9fIF0nq43zmk7KFT7/fGlXIbWcimuJKQZfTJxcMp9JK/H6YzEUTJntlFeXgYnCvLCzmRKr0i3UsgD2xJaJoOqvUtRwE3W2kZ/i8=","e":"AQAB"},
{"kty":"RSA","alg":"RS512","use":"sig","kid":"eu-central-11","n":"AL9Kz62JHMpn5kBEqyoaXkM56x3l3Wi0kg0Juv71QtXo5M4ZJYxouKdcrKfevYTRNm6DE0hTbJnyj7Bh4EYbmruGdSWE970xkcFJxcgak0j4rneRX5G1E/xN27M42OOLmZCe8O6l3nksD0XGOqBPqOSEP3pYCNAYMncpSGnit56fUX+yszfMjGP3DVSUFZKtXbqwt/S0VpBi5BQbbD57R8DKenQsPfln91tgGopmXP66vZ4yWRUzs/mqHxcez3FcgHHXc6AbEJ6GOSVd9t+BCUW5kVY0aYO301PJczvB3zfsI6qebjS6BFTvMp8SqK532ZRnXEMgs/5gc9cfxpDsgvk=","e":"AQAB"},
{"kty":"RSA","alg":"RS512","use":"sig","kid":"eu-west-11","n":"AKriovi9cnm+07tkfZMFFCvjfobq0TP1qjrQQ4uS91P3mt/Wy3bdVjMt6DfZeuowwfdQdcsc0XgDV1KHlIG5PKj3v6q6uH2M0mcqFpQZnIQ0xUbRoZkR6bHFgdRHR2GTbm79nh3z1gsaVYeDFGLrE7gXNQRAoKtClif4cW+ZmLAfS2nPFAg61pryh/HUdaN2zvfbTGZaB1zVL41tX5DncoQx3COLpIcdKIB//CpWO0iVubU7ZnNPRVt079t5MUpwgtyAnhqMzYWElsTAPopEWVMTxHJr1LUKXiU6nX1UoX8OxUtBCZ30xLddGXw6e8G7dZKxq/es+ov8r7IlmTI7OXM=","e":"AQAB"},
{"kty":"RSA","alg":"RS512","use":"sig","kid":"eu-west-21","n":"AKPfdgeKVzCBNDbaywRWIx2/g9IIs9s4BntmaRhbhCswYjkdMLeNC6ZAydxOn8NYYdAEE29bpHtF7jpoSe6fXShOv5n/sRVlRVWEo/NuTOVckLcpqRpcjm1ujM/CA/1O16w9MyHz8tmzapG9VikHdpCh8URkaPnyuEcO2+cOP1jAZ1P2U9bhx9cKxXfe1Vr9DrvDexCVqQ0vLw0ZbjN7nU2yAkim7O1CX6+fOMTsEMC+WX+fDb0RZVJ2hPqUT+dDY2Nnta69/8rI51C5f5+NVjKr+DgHYeaPGmq2AZ762PWsCKcNU8UgB+guXM2UxoRU+V0DLVWgtf8AxojhWgpJntM=","e":"AQAB"},
{"kty":"RSA","alg":"RS512","use":"sig","kid":"us-east-11","n":"AIvLE/h4h9XdAVyy0C7fn1ZXZ3Gt6YT2LPsHsoCUGgPAVJnLJjPRj3dSI2UmlWaLacSoHYeFABfxj8YROnE9fpiGto5LcdyfuRKET9Nv5UaZp0kMSSoF7wXinp07ACUbn+ZE3ImQR16r1/Q/j3AD4CmN7gVjk5+EZzVCTQtAzJZJ8/EgCPFE4YA0Q2UgFtBjZnt4SI8TljikBqUmNDVKyjh2yI+m4fQO/LZOEaI/aGOWYen4RrO+/3hTYk73b+oFCPnIp1sLNUmdAHzjIgWYCC2qBwC+tRWi7065ea2KYj+kNNFevXFYMrph3U1mxqDZSzIOvEXIlZqlhOoOc5NmWMc=","e":"AQAB"},
{"kty":"RSA","alg":"RS512","use":"sig","kid":"us-east-21","n":"AIrl+VgezCW0WK81WBUNl6CIuuP+nI7TnKgKvNKMdpuHmUhdwDJwxLr+Qe4G6jQSpHNzuwRoQ8zPxkkyeHP5722tmtjUFBtx6GJ6YCIGAIGNuFRIr3uWWLUVF8IVbLswq/XbuvN8oJNl0039AlUOgTI0SdHAGenQjOHTA2Mx274JDrK85UNC1euAzcEEdYmBHWE/llRLmjy5JexKS/i+B23S+18FA+W5s2+kDCnaIn3iHbMUzsoRdn616C738KxiCHIGYP9JSwYy/2IqqSeRE/0qLAxZ1cYU3UkihTSkzsCNnvhqOf3Hn5mR4onfh4iWEghV8lCS6wywFoxAuPMG6Uc=","e":"AQAB"},
{"kty":"RSA","alg":"RS512","use":"sig","kid":"us-west-21","n":"AJM4O/eTg8U00rbo/xXwECyAmpF8EUvbBj+nMvebhExjWyNhaEB27QvESbdM3FS+k8opxC5TKVqNCY8GGVAvHkTh5+BsaIeFrJLj22rXXs6E3bse5MBlmUHCIy8PQaZ/BpJWvlSz7IoprdfhgfOGvT96GgXouSytanvkU4A8a3jcmy2ZmdHSdeGLuAYQtdz+xP8zt2s2v2evFY/bEGQpd0EBlWsQKZvtZ0DJ1CtA/SJixbdhCj7bGh322QqgA8im+s3AAnD4I/UgfvZEAbkH6zqYgWTq5QnMsoizESf+6EmSDaJA4Bbkv1ffmcHuTEUwKnKZ+d7G5YXWwWndXu4tleM=","e":"AQAB"}]}`
	set, err := jwk.ParseString(src)
	if !assert.NoError(t, err, `parse should have succeeded`) {
		return
	}
	_ = set
}
