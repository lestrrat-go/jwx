package jwk_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/lestrrat-go/jwx/v2/internal/ecutil"
	"github.com/lestrrat-go/jwx/v2/internal/jose"
	"github.com/lestrrat-go/jwx/v2/internal/json"
	"github.com/lestrrat-go/jwx/v2/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v2/jws"

	"github.com/lestrrat-go/jwx/v2/internal/base64"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/x25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var zeroval reflect.Value
var certChain *cert.Chain
var certChainSrc = []string{
	"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",
}

type keyDef struct {
	Expected interface{}
	Value    interface{}
	Method   string
}

var commonDef map[string]keyDef

func init() {
	certChain = &cert.Chain{}
	for _, src := range certChainSrc {
		_ = certChain.AddString(src)
	}

	commonDef = map[string]keyDef{
		jwk.AlgorithmKey: {
			Method: "Algorithm",
			Value:  jwa.KeyAlgorithmFrom("random-algorithm"),
		},
		jwk.KeyIDKey: {
			Method: "KeyID",
			Value:  "12312rdfsdfer2342342",
		},
		jwk.KeyUsageKey: {
			Method:   "KeyUsage",
			Value:    jwk.ForSignature,
			Expected: string(jwk.ForSignature),
		},
		jwk.KeyOpsKey: {
			Method: "KeyOps",
			Value: jwk.KeyOperationList{
				jwk.KeyOpSign,
				jwk.KeyOpVerify,
				jwk.KeyOpEncrypt,
				jwk.KeyOpDecrypt,
				jwk.KeyOpWrapKey,
				jwk.KeyOpUnwrapKey,
				jwk.KeyOpDeriveKey,
				jwk.KeyOpDeriveBits,
			},
		},
		jwk.X509CertChainKey: {
			Method:   "X509CertChain",
			Value:    certChain,
			Expected: certChain,
		},
		jwk.X509CertThumbprintKey: {
			Value:  "x5t blah",
			Method: "X509CertThumbprint",
		},
		jwk.X509CertThumbprintS256Key: {
			Value:  "x5t#256 blah",
			Method: "X509CertThumbprintS256",
		},
		jwk.X509URLKey: {
			Value:  "http://github.com/lestrrat-go/jwx/v2",
			Method: "X509URL",
		},
		"private": {Value: "boofoo"},
	}
}

func complimentDef(def map[string]keyDef) map[string]keyDef {
	for k, v := range commonDef {
		if _, ok := def[k]; !ok {
			def[k] = v
		}
	}
	return def
}

func makeKeyJSON(def map[string]keyDef) []byte {
	data := map[string]interface{}{}
	for k, v := range def {
		data[k] = v.Value
	}
	src, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}
	return src
}

func expectBase64(kdef keyDef) keyDef {
	v, err := base64.DecodeString(kdef.Value.(string))
	if err != nil {
		panic(err)
	}
	kdef.Expected = v
	return kdef
}

func expectedRawKeyType(key jwk.Key) interface{} {
	switch key := key.(type) {
	case jwk.RSAPrivateKey:
		return &rsa.PrivateKey{}
	case jwk.RSAPublicKey:
		return &rsa.PublicKey{}
	case jwk.ECDSAPrivateKey:
		return &ecdsa.PrivateKey{}
	case jwk.ECDSAPublicKey:
		return &ecdsa.PublicKey{}
	case jwk.SymmetricKey:
		return []byte(nil)
	case jwk.OKPPrivateKey:
		switch key.Crv() {
		case jwa.Ed25519:
			return ed25519.PrivateKey(nil)
		case jwa.X25519:
			return x25519.PrivateKey(nil)
		default:
			panic("unknown curve type for OKPPrivateKey:" + key.Crv())
		}
	case jwk.OKPPublicKey:
		switch key.Crv() {
		case jwa.Ed25519:
			return ed25519.PublicKey(nil)
		case jwa.X25519:
			return x25519.PublicKey(nil)
		default:
			panic("unknown curve type for OKPPublicKey:" + key.Crv())
		}
	default:
		panic("unknown key type:" + reflect.TypeOf(key).String())
	}
}

func VerifyKey(t *testing.T, def map[string]keyDef) {
	t.Helper()

	def = complimentDef(def)
	key, err := jwk.ParseKey(makeKeyJSON(def))
	if !assert.NoError(t, err, `jwk.ParseKey should succeed`) {
		return
	}

	t.Run("Fields", func(t *testing.T) {
		for k, kdef := range def {
			k := k
			kdef := kdef
			t.Run(k, func(t *testing.T) {
				getval, ok := key.Get(k)
				if !assert.True(t, ok, `key.Get(%s) should succeed`, k) {
					return
				}
				expected := kdef.Expected
				if expected == nil {
					expected = kdef.Value
				}
				if !assert.Equal(t, expected, getval) {
					return
				}

				if mname := kdef.Method; mname != "" {
					method := reflect.ValueOf(key).MethodByName(mname)
					if !assert.NotEqual(t, zeroval, method, `method should not be a zero value`) {
						return
					}
					retvals := method.Call(nil)

					if !assert.Len(t, retvals, 1, `there should be 1 return value`) {
						return
					}

					if !assert.Equal(t, expected, retvals[0].Interface()) {
						return
					}
				}
			})
		}
	})
	t.Run("Roundtrip", func(t *testing.T) {
		var supportsPEM bool
		switch key.KeyType() {
		case jwa.OKP, jwa.OctetSeq:
		default:
			supportsPEM = true
		}

		for _, usePEM := range []bool{true, false} {
			if usePEM && !supportsPEM {
				continue
			}
			t.Run(fmt.Sprintf("WithPEM(%t)", usePEM), func(t *testing.T) {
				var buf []byte
				if usePEM {
					pem, err := jwk.EncodePEM(key)
					if !assert.NoError(t, err, `jwk.EncodePEM should succeed`) {
						return
					}
					buf = pem
				} else {
					jsonbuf, err := json.Marshal(key)
					if !assert.NoError(t, err, `json.Marshal should succeed`) {
						return
					}
					buf = jsonbuf
				}

				newkey, err := jwk.ParseKey(buf, jwk.WithPEM(usePEM))
				if !assert.NoError(t, err, `jwk.ParseKey should succeed`) {
					return
				}

				m1, err := key.AsMap(context.TODO())
				if !assert.NoError(t, err, `key.AsMap should succeed`) {
					return
				}

				m2, err := newkey.AsMap(context.TODO())
				if !assert.NoError(t, err, `key.AsMap should succeed`) {
					return
				}

				// PEM does not preserve these keys
				if usePEM {
					delete(m1, `private`)
					delete(m1, jwk.AlgorithmKey)
					delete(m1, jwk.KeyIDKey)
					delete(m1, jwk.KeyOpsKey)
					delete(m1, jwk.KeyUsageKey)
					delete(m1, jwk.X509CertChainKey)
					delete(m1, jwk.X509CertThumbprintKey)
					delete(m1, jwk.X509CertThumbprintS256Key)
					delete(m1, jwk.X509URLKey)
				}

				if !assert.Equal(t, m1, m2, `keys should match`) {
					return
				}
			})
		}
	})
	t.Run("Raw", func(t *testing.T) {
		typ := expectedRawKeyType(key)

		var rawkey interface{}
		if !assert.NoError(t, key.Raw(&rawkey), `Raw() should succeed`) {
			return
		}
		if !assert.IsType(t, rawkey, typ, `raw key should be of this type`) {
			return
		}
	})
	t.Run("PublicKey", func(t *testing.T) {
		_, err := jwk.PublicKeyOf(key)
		if !assert.NoError(t, err, `jwk.PublicKeyOf should succeed`) {
			return
		}
	})
	t.Run("Set/Remove", func(t *testing.T) {
		ctx := context.TODO()

		newkey, err := key.Clone()
		if !assert.NoError(t, err, `key.Clone should succeed`) {
			return
		}

		for iter := key.Iterate(ctx); iter.Next(ctx); {
			pair := iter.Pair()
			newkey.Remove(pair.Key.(string))
		}

		m, err := newkey.AsMap(ctx)
		if !assert.NoError(t, err, `key.AsMap should succeed`) {
			return
		}

		if !assert.Len(t, m, 1, `keys should have 1 key (kty remains)`) {
			return
		}

		for iter := key.Iterate(ctx); iter.Next(ctx); {
			pair := iter.Pair()
			if !assert.NoError(t, newkey.Set(pair.Key.(string), pair.Value), `newkey.Set should succeed`) {
				return
			}
		}
	})
}

func TestNew(t *testing.T) {
	t.Parallel()
	k, err := jwk.FromRaw(nil)
	if !assert.Nil(t, k, "key should be nil") {
		return
	}
	if !assert.Error(t, err, "nil key should cause an error") {
		return
	}
}

func TestParse(t *testing.T) {
	t.Parallel()
	verify := func(t *testing.T, src string, expected reflect.Type) {
		t.Helper()
		t.Run("json.Unmarshal", func(t *testing.T) {
			set := jwk.NewSet()
			if err := json.Unmarshal([]byte(src), set); !assert.NoError(t, err, `json.Unmarshal should succeed`) {
				return
			}

			if !assert.True(t, set.Len() > 0, "set.Keys should be greater than 0") {
				return
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			for iter := set.Keys(ctx); iter.Next(ctx); {
				pair := iter.Pair()
				if !assert.True(t, reflect.TypeOf(pair.Value).AssignableTo(expected), "key should be a %s", expected) {
					return
				}
			}
		})
		t.Run("jwk.Parse", func(t *testing.T) {
			t.Helper()
			set, err := jwk.Parse([]byte(`{"keys":[` + src + `]}`))
			if !assert.NoError(t, err, `jwk.Parse should succeed`) {
				return
			}

			if !assert.True(t, set.Len() > 0, "set.Len should be greater than 0") {
				return
			}

			for iter := set.Keys(context.TODO()); iter.Next(context.TODO()); {
				pair := iter.Pair()
				key := pair.Value.(jwk.Key)

				switch key := key.(type) {
				case jwk.RSAPrivateKey, jwk.ECDSAPrivateKey, jwk.OKPPrivateKey, jwk.RSAPublicKey, jwk.ECDSAPublicKey, jwk.OKPPublicKey, jwk.SymmetricKey:
				default:
					assert.Fail(t, fmt.Sprintf("invalid type: %T", key))
				}
			}
		})
		t.Run("jwk.ParseKey", func(t *testing.T) {
			t.Helper()
			key, err := jwk.ParseKey([]byte(src))
			if !assert.NoError(t, err, `jwk.ParseKey should succeed`) {
				return
			}

			t.Run("Raw", func(t *testing.T) {
				t.Helper()

				var irawkey interface{}
				if !assert.NoError(t, key.Raw(&irawkey), `key.Raw(&interface) should ucceed`) {
					return
				}

				var crawkey interface{}
				switch k := key.(type) {
				case jwk.RSAPrivateKey:
					var rawkey rsa.PrivateKey
					if !assert.NoError(t, key.Raw(&rawkey), `key.Raw(&rsa.PrivateKey) should succeed`) {
						return
					}
					crawkey = &rawkey
				case jwk.RSAPublicKey:
					var rawkey rsa.PublicKey
					if !assert.NoError(t, key.Raw(&rawkey), `key.Raw(&rsa.PublicKey) should succeed`) {
						return
					}
					crawkey = &rawkey
				case jwk.ECDSAPrivateKey:
					var rawkey ecdsa.PrivateKey
					if !assert.NoError(t, key.Raw(&rawkey), `key.Raw(&ecdsa.PrivateKey) should succeed`) {
						return
					}
					crawkey = &rawkey
				case jwk.OKPPrivateKey:
					switch k.Crv() {
					case jwa.Ed25519:
						var rawkey ed25519.PrivateKey
						if !assert.NoError(t, key.Raw(&rawkey), `key.Raw(&ed25519.PrivateKey) should succeed`) {
							return
						}
						crawkey = rawkey
					case jwa.X25519:
						var rawkey x25519.PrivateKey
						if !assert.NoError(t, key.Raw(&rawkey), `key.Raw(&x25519.PrivateKey) should succeed`) {
							return
						}
						crawkey = rawkey
					default:
						t.Errorf(`invalid curve %s`, k.Crv())
					}
				// NOTE: Has to come after private
				// key, since it's a subset of the
				// private key variant.
				case jwk.OKPPublicKey:
					switch k.Crv() {
					case jwa.Ed25519:
						var rawkey ed25519.PublicKey
						if !assert.NoError(t, key.Raw(&rawkey), `key.Raw(&ed25519.PublicKey) should succeed`) {
							return
						}
						crawkey = rawkey
					case jwa.X25519:
						var rawkey x25519.PublicKey
						if !assert.NoError(t, key.Raw(&rawkey), `key.Raw(&x25519.PublicKey) should succeed`) {
							return
						}
						crawkey = rawkey
					default:
						t.Errorf(`invalid curve %s`, k.Crv())
					}
				default:
					t.Errorf(`invalid key type %T`, key)
					return
				}

				if !assert.IsType(t, crawkey, irawkey, `key types should match`) {
					return
				}
			})
		})
		t.Run("ParseRawKey", func(t *testing.T) {
			var v interface{}
			if !assert.NoError(t, jwk.ParseRawKey([]byte(src), &v), `jwk.ParseRawKey should succeed`) {
				return
			}
		})
	}

	t.Run("RSA Public Key", func(t *testing.T) {
		t.Parallel()
		const src = `{
      "e":"AQAB",
			"kty":"RSA",
      "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
		}`
		verify(t, src, reflect.TypeOf((*jwk.RSAPublicKey)(nil)).Elem())
	})
	t.Run("RSA Private Key", func(t *testing.T) {
		t.Parallel()
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
		verify(t, src, reflect.TypeOf((*jwk.RSAPrivateKey)(nil)).Elem())
	})
	t.Run("ECDSA Private Key", func(t *testing.T) {
		t.Parallel()
		const src = `{
		  "kty" : "EC",
		  "crv" : "P-256",
		  "x"   : "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
		  "y"   : "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI",
		  "d"   : "0g5vAEKzugrXaRbgKG0Tj2qJ5lMP4Bezds1_sTybkfk"
		}`
		verify(t, src, reflect.TypeOf((*jwk.ECDSAPrivateKey)(nil)).Elem())
	})
	t.Run("Invalid ECDSA Private Key", func(t *testing.T) {
		t.Parallel()
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
	t.Run("Ed25519 Public Key", func(t *testing.T) {
		t.Parallel()
		// Key taken from RFC 8037
		const src = `{
		  "kty" : "OKP",
		  "crv" : "Ed25519",
		  "x"   : "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
		}`
		verify(t, src, reflect.TypeOf((*jwk.OKPPublicKey)(nil)).Elem())
	})
	t.Run("Ed25519 Private Key", func(t *testing.T) {
		t.Parallel()
		// Key taken from RFC 8037
		const src = `{
		  "kty" : "OKP",
		  "crv" : "Ed25519",
		  "d"   : "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
		  "x"   : "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
		}`
		verify(t, src, reflect.TypeOf((*jwk.OKPPrivateKey)(nil)).Elem())
	})
	t.Run("X25519 Public Key", func(t *testing.T) {
		t.Parallel()
		// Key taken from RFC 8037
		const src = `{
		  "kty" : "OKP",
		  "crv" : "X25519",
		  "x"   : "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"
		}`
		verify(t, src, reflect.TypeOf((*jwk.OKPPublicKey)(nil)).Elem())
	})
	t.Run("X25519 Private Key", func(t *testing.T) {
		t.Parallel()
		// Key taken from RFC 8037
		const src = `{
		  "kty" : "OKP",
		  "crv" : "X25519",
		  "d"   : "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo",
		  "x"   : "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"
		}`
		verify(t, src, reflect.TypeOf((*jwk.OKPPrivateKey)(nil)).Elem())
	})
}

func TestRoundtrip(t *testing.T) {
	t.Parallel()
	generateRSA := func(use string, keyID string) (jwk.Key, error) {
		k, err := jwxtest.GenerateRsaJwk()
		if err != nil {
			return nil, err
		}

		k.Set(jwk.KeyUsageKey, use)
		k.Set(jwk.KeyIDKey, keyID)
		return k, nil
	}

	generateECDSA := func(use, keyID string) (jwk.Key, error) {
		k, err := jwxtest.GenerateEcdsaJwk()
		if err != nil {
			return nil, err
		}

		k.Set(jwk.KeyUsageKey, use)
		k.Set(jwk.KeyIDKey, keyID)
		return k, nil
	}

	generateSymmetric := func(use, keyID string) (jwk.Key, error) {
		k, err := jwxtest.GenerateSymmetricJwk()
		if err != nil {
			return nil, err
		}

		k.Set(jwk.KeyUsageKey, use)
		k.Set(jwk.KeyIDKey, keyID)
		return k, nil
	}

	generateEd25519 := func(use, keyID string) (jwk.Key, error) {
		k, err := jwxtest.GenerateEd25519Jwk()
		if err != nil {
			return nil, err
		}

		k.Set(jwk.KeyUsageKey, use)
		k.Set(jwk.KeyIDKey, keyID)
		return k, nil
	}

	generateX25519 := func(use, keyID string) (jwk.Key, error) {
		k, err := jwxtest.GenerateX25519Jwk()
		if err != nil {
			return nil, err
		}

		k.Set(jwk.KeyUsageKey, use)
		k.Set(jwk.KeyIDKey, keyID)
		return k, nil
	}

	tests := []struct {
		generate func(string, string) (jwk.Key, error)
		use      string
		keyID    string
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
		{
			use:      "sig",
			keyID:    "sig6",
			generate: generateEd25519,
		},
		{
			use:      "enc",
			keyID:    "enc6",
			generate: generateX25519,
		},
	}

	ks1 := jwk.NewSet()
	for _, tc := range tests {
		key, err := tc.generate(tc.use, tc.keyID)
		if !assert.NoError(t, err, `tc.generate should succeed`) {
			return
		}
		if !assert.NoError(t, ks1.AddKey(key), `ks1.Add should succeed`) {
			return
		}
	}

	buf, err := json.MarshalIndent(ks1, "", "  ")
	if !assert.NoError(t, err, "JSON marshal succeeded") {
		return
	}

	ks2, err := jwk.Parse(buf)
	if !assert.NoError(t, err, "JSON unmarshal succeeded") {
		t.Logf("%s", buf)
		return
	}

	for _, tc := range tests {
		key1, ok := ks2.LookupKeyID(tc.keyID)
		if !assert.True(t, ok, "ks2.LookupKeyID should succeed") {
			return
		}

		key2, ok := ks1.LookupKeyID(tc.keyID)
		if !assert.True(t, ok, "ks1.LookupKeyID should succeed") {
			return
		}

		pk1json, _ := json.Marshal(key1)
		pk2json, _ := json.Marshal(key2)
		if !assert.Equal(t, pk1json, pk2json, "Keys should match (kid = %s)", tc.keyID) {
			return
		}
	}
}

func TestAccept(t *testing.T) {
	t.Parallel()
	t.Run("KeyOperation", func(t *testing.T) {
		t.Parallel()
		testcases := []struct {
			Args  interface{}
			Error bool
		}{
			{
				Args: "sign",
			},
			{
				Args: []jwk.KeyOperation{jwk.KeyOpSign, jwk.KeyOpVerify, jwk.KeyOpEncrypt, jwk.KeyOpDecrypt, jwk.KeyOpWrapKey, jwk.KeyOpUnwrapKey},
			},
			{
				Args: jwk.KeyOperationList{jwk.KeyOpSign, jwk.KeyOpVerify, jwk.KeyOpEncrypt, jwk.KeyOpDecrypt, jwk.KeyOpWrapKey, jwk.KeyOpUnwrapKey},
			},
			{
				Args: []interface{}{"sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey"},
			},
			{
				Args: []string{"sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey"},
			},
			{
				Args:  []string{"sigh"},
				Error: true,
			},
		}

		for _, test := range testcases {
			var ops jwk.KeyOperationList
			if test.Error {
				if !assert.Error(t, ops.Accept(test.Args), `KeyOperationList.Accept should fail`) {
					return
				}
			} else {
				if !assert.NoError(t, ops.Accept(test.Args), `KeyOperationList.Accept should succeed`) {
					return
				}
			}
		}
	})
	t.Run("KeyUsage", func(t *testing.T) {
		t.Parallel()
		testcases := []struct {
			Args  interface{}
			Error bool
		}{
			{Args: jwk.ForSignature},
			{Args: jwk.ForEncryption},
			{Args: jwk.ForSignature.String()},
			{Args: jwk.ForEncryption.String()},
			{Args: jwk.KeyUsageType("bogus"), Error: true},
			{Args: "bogus", Error: true},
		}
		for _, test := range testcases {
			var usage jwk.KeyUsageType
			if test.Error {
				if !assert.Error(t, usage.Accept(test.Args), `KeyUsage.Accept should fail`) {
					return
				}
			} else {
				if !assert.NoError(t, usage.Accept(test.Args), `KeyUsage.Accept should succeed`) {
					return
				}
			}
		}
	})
}

func TestAssignKeyID(t *testing.T) {
	t.Parallel()
	generators := []func() (jwk.Key, error){
		jwxtest.GenerateRsaJwk,
		jwxtest.GenerateRsaPublicJwk,
		jwxtest.GenerateEcdsaJwk,
		jwxtest.GenerateEcdsaPublicJwk,
		jwxtest.GenerateSymmetricJwk,
		jwxtest.GenerateEd25519Jwk,
	}

	for _, generator := range generators {
		k, err := generator()
		if !assert.NoError(t, err, `jwk generation should be successful`) {
			return
		}

		if !assert.Empty(t, k.KeyID(), `k.KeyID should be non-empty`) {
			return
		}
		if !assert.NoError(t, jwk.AssignKeyID(k), `AssignKeyID shuld be successful`) {
			return
		}

		if !assert.NotEmpty(t, k.KeyID(), `k.KeyID should be non-empty`) {
			return
		}
	}
}

func TestPublicKeyOf(t *testing.T) {
	t.Parallel()

	rsakey, err := jwxtest.GenerateRsaKey()
	if !assert.NoError(t, err, `generating raw RSA key should succeed`) {
		return
	}

	ecdsakey, err := jwxtest.GenerateEcdsaKey(jwa.P521)
	if !assert.NoError(t, err, `generating raw ECDSA key should succeed`) {
		return
	}

	octets := jwxtest.GenerateSymmetricKey()

	ed25519key, err := jwxtest.GenerateEd25519Key()
	if !assert.NoError(t, err, `generating raw Ed25519 key should succeed`) {
		return
	}

	x25519key, err := jwxtest.GenerateX25519Key()
	if !assert.NoError(t, err, `generating raw X25519 key should succeed`) {
		return
	}

	keys := []struct {
		Key           interface{}
		PublicKeyType reflect.Type
	}{
		{
			Key:           rsakey,
			PublicKeyType: reflect.PtrTo(reflect.TypeOf(rsakey.PublicKey)),
		},
		{
			Key:           *rsakey,
			PublicKeyType: reflect.PtrTo(reflect.TypeOf(rsakey.PublicKey)),
		},
		{
			Key:           rsakey.PublicKey,
			PublicKeyType: reflect.PtrTo(reflect.TypeOf(rsakey.PublicKey)),
		},
		{
			Key:           &rsakey.PublicKey,
			PublicKeyType: reflect.PtrTo(reflect.TypeOf(rsakey.PublicKey)),
		},
		{
			Key:           ecdsakey,
			PublicKeyType: reflect.PtrTo(reflect.TypeOf(ecdsakey.PublicKey)),
		},
		{
			Key:           *ecdsakey,
			PublicKeyType: reflect.PtrTo(reflect.TypeOf(ecdsakey.PublicKey)),
		},
		{
			Key:           ecdsakey.PublicKey,
			PublicKeyType: reflect.PtrTo(reflect.TypeOf(ecdsakey.PublicKey)),
		},
		{
			Key:           &ecdsakey.PublicKey,
			PublicKeyType: reflect.PtrTo(reflect.TypeOf(ecdsakey.PublicKey)),
		},
		{
			Key:           octets,
			PublicKeyType: reflect.TypeOf(octets),
		},
		{
			Key:           ed25519key,
			PublicKeyType: reflect.TypeOf(ed25519key.Public()),
		},
		{
			Key:           ed25519key.Public(),
			PublicKeyType: reflect.TypeOf(ed25519key.Public()),
		},
		{
			Key:           x25519key,
			PublicKeyType: reflect.TypeOf(x25519key.Public()),
		},
		{
			Key:           x25519key.Public(),
			PublicKeyType: reflect.TypeOf(x25519key.Public()),
		},
	}

	for _, key := range keys {
		key := key
		t.Run(fmt.Sprintf("%T", key.Key), func(t *testing.T) {
			t.Parallel()

			pubkey, err := jwk.PublicRawKeyOf(key.Key)
			if !assert.NoError(t, err, `jwk.PublicKeyOf(%T) should succeed`, key.Key) {
				return
			}

			if !assert.Equal(t, key.PublicKeyType, reflect.TypeOf(pubkey), `public key types should match (got %T)`, pubkey) {
				return
			}

			// Go through jwk.FromRaw
			jwkKey, err := jwk.FromRaw(key.Key)
			if !assert.NoError(t, err, `jwk.FromRaw should succeed`) {
				return
			}

			pubJwkKey, err := jwk.PublicKeyOf(jwkKey)
			if !assert.NoError(t, err, `jwk.PublicKeyOf(%T) should succeed`, jwkKey) {
				return
			}

			// Get the raw key to compare
			var rawKey interface{}
			if !assert.NoError(t, pubJwkKey.Raw(&rawKey), `pubJwkKey.Raw should succeed`) {
				return
			}

			if !assert.Equal(t, key.PublicKeyType, reflect.TypeOf(rawKey), `public key types should match (got %T)`, rawKey) {
				return
			}
		})
	}
	t.Run("Set", func(t *testing.T) {
		var setKeys []struct {
			Key           jwk.Key
			PublicKeyType reflect.Type
		}
		set := jwk.NewSet()
		count := 0
		for _, key := range keys {
			if reflect.TypeOf(key.Key) == key.PublicKeyType {
				continue
			}
			jwkKey, err := jwk.FromRaw(key.Key)
			if !assert.NoError(t, err, `jwk.FromRaw should succeed`) {
				return
			}
			jwkKey.Set(jwk.KeyIDKey, fmt.Sprintf("key%d", count))
			setKeys = append(setKeys, struct {
				Key           jwk.Key
				PublicKeyType reflect.Type
			}{
				Key:           jwkKey,
				PublicKeyType: key.PublicKeyType,
			})
			set.AddKey(jwkKey)
			count++
		}

		newSet, err := jwk.PublicSetOf(set)
		if !assert.NoError(t, err, `jwk.PublicKeyOf(jwk.Set) should succeed`) {
			return
		}

		for i, key := range setKeys {
			setKey, ok := newSet.Key(i)
			if !assert.True(t, ok, `element %d should be present`, i) {
				return
			}

			if !assert.Equal(t, fmt.Sprintf("key%d", i), setKey.KeyID(), `KeyID() should match for %T`, setKey) {
				return
			}

			// Get the raw key to compare
			var rawKey interface{}
			if !assert.NoError(t, setKey.Raw(&rawKey), `pubJwkKey.Raw should succeed`) {
				return
			}

			if !assert.Equal(t, key.PublicKeyType, reflect.TypeOf(rawKey), `public key types should match (got %T)`, rawKey) {
				return
			}
		}
	})
}

func TestIssue207(t *testing.T) {
	t.Parallel()
	const src = `{"kty":"EC","alg":"ECMR","crv":"P-521","key_ops":["deriveKey"],"x":"AJwCS845x9VljR-fcrN2WMzIJHDYuLmFShhyu8ci14rmi2DMFp8txIvaxG8n7ZcODeKIs1EO4E_Bldm_pxxs8cUn","y":"ASjz754cIQHPJObihPV8D7vVNfjp_nuwP76PtbLwUkqTk9J1mzCDKM3VADEk-Z1tP-DHiwib6If8jxnb_FjNkiLJ"}`

	// Using a loop here because we're using sync.Pool
	// just for sanity.
	for i := 0; i < 10; i++ {
		k, err := jwk.ParseKey([]byte(src))
		if !assert.NoError(t, err, `jwk.ParseKey should succeed`) {
			return
		}

		thumb, err := k.Thumbprint(crypto.SHA1)
		if !assert.NoError(t, err, `k.Thumbprint should succeed`) {
			return
		}

		if !assert.Equal(t, `2Mc_43O_BOrOJTNrGX7uJ6JsIYE`, base64.EncodeToString(thumb), `thumbprints should match`) {
			return
		}
	}
}

func TestIssue270(t *testing.T) {
	t.Parallel()
	const src = `{"kty":"EC","alg":"ECMR","crv":"P-521","key_ops":["deriveKey"],"x":"AJwCS845x9VljR-fcrN2WMzIJHDYuLmFShhyu8ci14rmi2DMFp8txIvaxG8n7ZcODeKIs1EO4E_Bldm_pxxs8cUn","y":"ASjz754cIQHPJObihPV8D7vVNfjp_nuwP76PtbLwUkqTk9J1mzCDKM3VADEk-Z1tP-DHiwib6If8jxnb_FjNkiLJ"}`
	k, err := jwk.ParseKey([]byte(src))
	if !assert.NoError(t, err, `jwk.ParseKey should succeed`) {
		return
	}

	for _, usage := range []string{"sig", "enc"} {
		if !assert.NoError(t, k.Set(jwk.KeyUsageKey, usage)) {
			return
		}
		if !assert.NoError(t, k.Set(jwk.KeyUsageKey, jwk.KeyUsageType(usage))) {
			return
		}
	}
}

func TestReadFile(t *testing.T) {
	t.Parallel()
	if !jose.Available() {
		t.SkipNow()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fn, clean, err := jose.GenerateJwk(ctx, t, `{"alg": "RS256"}`)
	if !assert.NoError(t, err, `jose.GenerateJwk`) {
		return
	}

	defer clean()
	if _, err := jwk.ReadFile(fn); !assert.NoError(t, err, `jwk.ReadFile should succeed`) {
		return
	}
}

func TestRSA(t *testing.T) {
	t.Parallel()
	t.Run("PublicKey", func(t *testing.T) {
		t.Parallel()
		VerifyKey(t, map[string]keyDef{
			jwk.RSAEKey: expectBase64(keyDef{
				Method: "E",
				Value:  "AQAB",
			}),
			jwk.KeyTypeKey: {
				Method: "KeyType",
				Value:  jwa.RSA,
			},
			jwk.RSANKey: expectBase64(keyDef{
				Method: "N",
				Value:  "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
			}),
		})
		t.Run("New", func(t *testing.T) {
			for _, raw := range []rsa.PublicKey{
				{},
			} {
				_, err := jwk.FromRaw(raw)
				if !assert.Error(t, err, `jwk.FromRaw should fail for invalid key`) {
					return
				}
			}
		})
	})
	t.Run("Private Key", func(t *testing.T) {
		t.Parallel()
		VerifyKey(t, map[string]keyDef{
			jwk.KeyTypeKey: {
				Method: "KeyType",
				Value:  jwa.RSA,
			},
			jwk.RSANKey: expectBase64(keyDef{
				Method: "N",
				Value:  "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
			}),
			jwk.RSAEKey: expectBase64(keyDef{
				Method: "E",
				Value:  "AQAB",
			}),
			jwk.RSADKey: expectBase64(keyDef{
				Method: "D",
				Value:  "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
			}),
			jwk.RSAPKey: expectBase64(keyDef{
				Method: "P",
				Value:  "83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
			}),
			jwk.RSAQKey: expectBase64(keyDef{
				Method: "Q",
				Value:  "3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
			}),
			jwk.RSADPKey: expectBase64(keyDef{
				Method: "DP",
				Value:  "G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
			}),
			jwk.RSADQKey: expectBase64(keyDef{
				Method: "DQ",
				Value:  "s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
			}),
			jwk.RSAQIKey: expectBase64(keyDef{
				Method: "QI",
				Value:  "GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
			}),
		})
		t.Run("New", func(t *testing.T) {
			for _, raw := range []rsa.PrivateKey{
				{}, // Missing D
				{ // Missing primes
					D: &big.Int{},
				},
				{ // Missing Primes[0]
					D:      &big.Int{},
					Primes: []*big.Int{nil, {}},
				},
				{ // Missing Primes[1]
					D:      &big.Int{},
					Primes: []*big.Int{{}, nil},
				},
				{ // Missing PrivateKey.N
					D:      &big.Int{},
					Primes: []*big.Int{{}, {}},
				},
			} {
				_, err := jwk.FromRaw(raw)
				if !assert.Error(t, err, `jwk.FromRaw should fail for empty key`) {
					return
				}
			}
		})
	})
	t.Run("Thumbprint", func(t *testing.T) {
		expected := []byte{55, 54, 203, 177, 120, 124, 184, 48, 156, 119, 238,
			140, 55, 5, 197, 225, 111, 251, 158, 133, 151, 21, 144, 31, 30, 76, 89,
			177, 17, 130, 245, 123,
		}
		const src = `{
	   			"kty":"RSA",
	   			"e": "AQAB",
	   			"n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
	   		}`

		key, err := jwk.ParseKey([]byte(src))
		if !assert.NoError(t, err, `jwk.ParseKey should succeed`) {
			return
		}

		tp, err := key.Thumbprint(crypto.SHA256)
		if !assert.NoError(t, err, "Thumbprint should succeed") {
			return
		}

		if !assert.Equal(t, expected, tp, "Thumbprint should match") {
			return
		}
	})
}

func TestECDSA(t *testing.T) {
	t.Run("PrivateKey", func(t *testing.T) {
		t.Run("New", func(t *testing.T) {
			for _, raw := range []ecdsa.PrivateKey{
				{},
				{ // Missing PublicKey
					D: &big.Int{},
				},
				{ // Missing PublicKey.X
					D: &big.Int{},
					PublicKey: ecdsa.PublicKey{
						Y: &big.Int{},
					},
				},
				{ // Missing PublicKey.Y
					D: &big.Int{},
					PublicKey: ecdsa.PublicKey{
						X: &big.Int{},
					},
				},
			} {
				_, err := jwk.FromRaw(raw)
				if !assert.Error(t, err, `jwk.FromRaw should fail for invalid key`) {
					return
				}
			}
		})
		VerifyKey(t, map[string]keyDef{
			jwk.KeyTypeKey: {
				Method: "KeyType",
				Value:  jwa.EC,
			},
			jwk.ECDSACrvKey: {
				Method: "Crv",
				Value:  jwa.P256,
			},
			jwk.ECDSAXKey: expectBase64(keyDef{
				Method: "X",
				Value:  "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
			}),
			jwk.ECDSAYKey: expectBase64(keyDef{
				Method: "Y",
				Value:  "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
			}),
			jwk.ECDSADKey: expectBase64(keyDef{
				Method: "D",
				Value:  "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
			}),
		})
	})
	t.Run("PublicKey", func(t *testing.T) {
		t.Run("New", func(t *testing.T) {
			for _, raw := range []ecdsa.PublicKey{
				{},
				{ // Missing X
					Y: &big.Int{},
				},
				{ // Missing Y
					X: &big.Int{},
				},
			} {
				_, err := jwk.FromRaw(raw)
				if !assert.Error(t, err, `jwk.FromRaw should fail for invalid key`) {
					return
				}
			}
		})
		VerifyKey(t, map[string]keyDef{
			jwk.KeyTypeKey: {
				Method: "KeyType",
				Value:  jwa.EC,
			},
			jwk.ECDSACrvKey: {
				Method: "Crv",
				Value:  jwa.P256,
			},
			jwk.ECDSAXKey: expectBase64(keyDef{
				Method: "X",
				Value:  "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
			}),
			jwk.ECDSAYKey: expectBase64(keyDef{
				Method: "Y",
				Value:  "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
			}),
		})
	})
	t.Run("Curve types", func(t *testing.T) {
		for _, alg := range ecutil.AvailableAlgorithms() {
			alg := alg
			t.Run(alg.String(), func(t *testing.T) {
				key, err := jwxtest.GenerateEcdsaKey(alg)
				if !assert.NoError(t, err, `jwxtest.GenerateEcdsaKey should succeed`) {
					return
				}

				privkey, err := jwk.FromRaw(key)
				if !assert.NoError(t, err, `jwk.FromRaw should succeed`) {
					return
				}
				pubkey, err := jwk.FromRaw(key)
				if !assert.NoError(t, err, `jwk.FromRaw should succeed`) {
					return
				}

				privtp, err := privkey.Thumbprint(crypto.SHA512)
				if !assert.NoError(t, err, `privkey.Thumbprint should succeed`) {
					return
				}

				pubtp, err := pubkey.Thumbprint(crypto.SHA512)
				if !assert.NoError(t, err, `pubkey.Thumbprint should succeed`) {
					return
				}

				if !assert.Equal(t, privtp, pubtp, `Thumbprints should match`) {
					return
				}
			})
		}
	})
}

func TestSymmetric(t *testing.T) {
	t.Run("Key", func(t *testing.T) {
		VerifyKey(t, map[string]keyDef{
			jwk.KeyTypeKey: {
				Method: "KeyType",
				Value:  jwa.OctetSeq,
			},
			jwk.SymmetricOctetsKey: expectBase64(keyDef{
				Method: "Octets",
				Value:  "aGVsbG8K",
			}),
		})
	})
}

func TestOKP(t *testing.T) {
	t.Parallel()

	t.Run("Ed25519", func(t *testing.T) {
		t.Parallel()
		t.Run("PrivateKey", func(t *testing.T) {
			t.Parallel()
			VerifyKey(t, map[string]keyDef{
				jwk.KeyTypeKey: {
					Method: "KeyType",
					Value:  jwa.OKP,
				},
				jwk.OKPDKey: expectBase64(keyDef{
					Method: "D",
					Value:  "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
				}),
				jwk.OKPXKey: expectBase64(keyDef{
					Method: "X",
					Value:  "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
				}),
				jwk.OKPCrvKey: {
					Method: "Crv",
					Value:  jwa.Ed25519,
				},
			})
		})
		t.Run("PublicKey", func(t *testing.T) {
			t.Parallel()
			VerifyKey(t, map[string]keyDef{
				jwk.KeyTypeKey: {
					Method: "KeyType",
					Value:  jwa.OKP,
				},
				jwk.OKPXKey: expectBase64(keyDef{
					Method: "X",
					Value:  "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
				}),
				jwk.OKPCrvKey: {
					Method: "Crv",
					Value:  jwa.Ed25519,
				},
			})
		})
	})
	t.Run("X25519", func(t *testing.T) {
		t.Parallel()
		t.Run("PublicKey", func(t *testing.T) {
			t.Parallel()
			VerifyKey(t, map[string]keyDef{
				jwk.KeyTypeKey: {
					Method: "KeyType",
					Value:  jwa.OKP,
				},
				jwk.OKPXKey: expectBase64(keyDef{
					Method: "X",
					Value:  "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08",
				}),
				jwk.OKPCrvKey: {
					Method: "Crv",
					Value:  jwa.X25519,
				},
			})
		})
	})
}

func TestCustomField(t *testing.T) {
	// XXX has global effect!!!
	jwk.RegisterCustomField(`x-birthday`, time.Time{})
	defer jwk.RegisterCustomField(`x-birthday`, nil)

	expected := time.Date(2015, 11, 4, 5, 12, 52, 0, time.UTC)
	bdaybytes, _ := expected.MarshalText() // RFC3339

	var b strings.Builder
	b.WriteString(`{"e":"AQAB", "kty":"RSA", "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","x-birthday":"`)
	b.Write(bdaybytes)
	b.WriteString(`"}`)
	src := b.String()

	t.Run("jwk.ParseKey", func(t *testing.T) {
		key, err := jwk.ParseKey([]byte(src))
		if !assert.NoError(t, err, `jwk.ParseKey should succeed`) {
			return
		}

		v, ok := key.Get(`x-birthday`)
		if !assert.True(t, ok, `key.Get("x-birthday") should succeed`) {
			return
		}

		if !assert.Equal(t, expected, v, `values should match`) {
			return
		}
	})
}

func TestCertificate(t *testing.T) {
	const src = `-----BEGIN CERTIFICATE-----
MIIEljCCAn4CCQCTQBoGDvUbQTANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJK
UDAeFw0yMTA0MDEwMDE4MjhaFw0yMjA0MDEwMDE4MjhaMA0xCzAJBgNVBAYTAkpQ
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvws4H/OxVS3CW1zvUgjs
H443df9zCAblLVPPdeRD11Jl1OZmGS7rtQNjQyT5xGpeuk77ZJcfDNLx+mSEtiYQ
V37GD5MPz+RX3hP2azuLvxoBseaHE6kC8tkDed8buQLl1hgms15KmKnt7E8B+EK2
1YRj0w6ZzehIllTbbj6gDJ39kZ2VHdLf5+4W0Kyh9cM4aA0si2jQJQsohW2rpt89
b+IagFau+sxP3GFUjSEvyXIamXhS0NLWuAW9UvY/RwhnIo5BzmWZd/y2R305T+QT
rHtb/8aGav8mP3uDx6AMDp/0UMKFUO4mpoOusMnrplUPS4Lz6RNpffmrrglOEuRZ
/eSFzGL35OeL12aYSyrbFIVsc/aLs6MkoplsuSG6Zhx345h/dA2a8Ub5khr6bksP
zGLer+bpBrQQsy21unvCIUz5y7uaYhV3Ql+aIZ+dwpEgZ3xxAvdKKeoCGQlhH/4J
0sSuutUtuTLfrBSgLHJEv2HIzeynChL2CYR8aku/nL68VTdmSt9UY2JGMOf9U8BI
fGRpkWBvI8hddMxNm8wF+09WScaZ2JWu7qW/l2jOdgesPIWRg+Hm3NaRSHqAWCOq
VUJk9WkCAye0FPALqSvH0ApDKxNtGZb5JZRCW19TqmhgXbAqIf5hsxDaGIXZcW9S
CqapZPw7Ccs7BOKSFvmM9p0CAwEAATANBgkqhkiG9w0BAQsFAAOCAgEAVfLzKRdA
0vFpAAp3K+CDth7mag2WWFOXjlWZ+4pxfEBX3k7erJbj6+qYuCvCHXqIZnK1kZzD
p4zwsu8t8RfSmPvxcm/jkvecG4DAIGTdhBVtAf/9PU3e4kZFQCqizicQABh+ZFKV
dDtkRebUA5EAvP8E/OrvrjYU5xnOxOZU3arVXJfKFjVD619qLuF8XXW5700Gdqwn
wBgasTCCg9+tniiscKaET1m9C4PdrlXuAIscV9tGcJ7yEAao1BXokyJ+mK6K2Zv1
z/vvUJA/rGMBJoUjnWrRHON1JMNou2KyRO6z37GpRnfPiNgFpGv2x3ZNeix7H4bP
6+x4KZWQir5047p9hV4YrqMXeULEj3uG2GnOgdR7+hiN39arFVr11DMgABmx19SM
VQpTHrC8a605wwCBWnkiYdNojLa5WgeEHdBghKVpWnx9frYgZcz2UP861el5Lg9R
j04wkGL4IORYiM7VHSHNU4u/dlgfQE1y0T+1CzXwquy4csvbBzBKnZ1o9ZBsOtWS
ox0RaBsMD70mvTwKKmlCSD5HgZZTC0CfGWk4dQp/Mct5Z0x0HJMEJCJzpgTn3CRX
z8CjezfckLs7UKJOlhu3OU9TFsiGDzSDBZdDWO1/uciJ/AAWeSmsBt8cKL0MirIr
c4wOvhbalcX0FqTM3mXCgMFRbibquhwdxbU=
-----END CERTIFICATE-----`
	key, err := jwk.ParseKey([]byte(src), jwk.WithPEM(true))
	if !assert.NoError(t, err, `jwk.ParseKey should succeed`) {
		return
	}

	if !assert.Equal(t, jwa.RSA, key.KeyType(), `key type should be RSA`) {
		return
	}

	var pubkey rsa.PublicKey
	if !assert.NoError(t, key.Raw(&pubkey), `key.Raw should succeed`) {
		return
	}

	N := &big.Int{}
	N, _ = N.SetString(`779390807991489150242580488277564408218067197694419403671246387831173881192316375931050469298375090533614189460270485948672580508192398132571230359681952349714254730569052029178325305344289615160181016909374016900403698428293142159695593998453788610098596363011884623801134548926432366560975619087466760747503535615491182090094278093592303467050094984372887804234341012289019841973178427045121609424191835554013017436743418746919496835541323790719629313070434897002108079086472354410640690933161025543816362962891190753195691593288890628966181309776957070655619665306995097798188588453327627252794498823229009195585001242181503742627414517186199717150645163224325403559815442522031412813762764879089624715721999552786759649849125487587658121901233329199571710176245013452847516179837767710027433169340850618643815395642568876192931279303797384539146396956216244189819533317558165234451499206045369678277987397913889177569796721689284116762473340601498426367267765652880247655009239893325078809797979771964770948333084772104541394544131668212262901583064272659565503500144472388676955404823979083054620299811247635425415371418720649368570747531327436083928369741631909855731133100553629456091216238379430154237251461586878393695925917`, 10)

	if !assert.Equal(t, N, pubkey.N, `value for N should match`) {
		return
	}

	if !assert.Equal(t, 65537, pubkey.E, `value for E should amtch`) {
		return
	}
}

type typedField struct {
	Foo string
	Bar int
}

func TestTypedFields(t *testing.T) {
	expected := &typedField{Foo: "Foo", Bar: 0xdeadbeef}
	var keys []jwk.Key
	{
		k1, _ := jwxtest.GenerateRsaJwk()
		k2, _ := jwxtest.GenerateEcdsaJwk()
		k3, _ := jwxtest.GenerateSymmetricJwk()
		k4, _ := jwxtest.GenerateEd25519Jwk()
		keys = []jwk.Key{k1, k2, k3, k4}
	}
	for _, key := range keys {
		key.Set("typed-field", expected)
	}

	testcases := []struct {
		Name        string
		Options     []jwk.ParseOption
		PostProcess func(*testing.T, interface{}) (*typedField, error)
	}{
		{
			Name:    "Basic",
			Options: []jwk.ParseOption{jwk.WithTypedField("typed-field", typedField{})},
			PostProcess: func(t *testing.T, field interface{}) (*typedField, error) {
				t.Helper()
				v, ok := field.(typedField)
				if !ok {
					return nil, fmt.Errorf(`field value should be of type "typedField", but got %T`, field)
				}
				return &v, nil
			},
		},
		{
			Name:    "json.RawMessage",
			Options: []jwk.ParseOption{jwk.WithTypedField("typed-field", json.RawMessage{})},
			PostProcess: func(t *testing.T, field interface{}) (*typedField, error) {
				t.Helper()
				v, ok := field.(json.RawMessage)
				if !ok {
					return nil, fmt.Errorf(`field value should be of type "json.RawMessage", but got %T`, field)
				}

				var c typedField
				if err := json.Unmarshal(v, &c); err != nil {
					return nil, fmt.Errorf(`json.Unmarshal failed: %w`, err)
				}

				return &c, nil
			},
		},
	}

	for _, key := range keys {
		key := key
		serialized, err := json.Marshal(key)
		if !assert.NoError(t, err, `json.Marshal should succeed`) {
			return
		}

		t.Run(fmt.Sprintf("%T", key), func(t *testing.T) {
			for _, tc := range testcases {
				tc := tc
				t.Run(tc.Name, func(t *testing.T) {
					got, err := jwk.ParseKey(serialized, tc.Options...)
					if !assert.NoError(t, err, `jwk.Parse should succeed`) {
						return
					}

					v, ok := got.Get("typed-field")
					if !assert.True(t, ok, `got.Get() should succeed`) {
						return
					}
					field, err := tc.PostProcess(t, v)
					if !assert.NoError(t, err, `tc.PostProcess should succeed`) {
						return
					}

					if !assert.Equal(t, field, expected, `field should match expected value`) {
						return
					}
				})
			}
		})
	}

	t.Run("Set", func(t *testing.T) {
		s := jwk.NewSet()
		for _, key := range keys {
			s.AddKey(key)
		}

		serialized, err := json.Marshal(s)
		if !assert.NoError(t, err, `json.Marshal should succeed`) {
			return
		}

		for _, tc := range testcases {
			tc := tc
			t.Run(tc.Name, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				got, err := jwk.Parse(serialized, tc.Options...)
				if !assert.NoError(t, err, `jwk.Parse should succeed`) {
					return
				}

				for iter := got.Keys(ctx); iter.Next(ctx); {
					pair := iter.Pair()
					key, _ := pair.Value.(jwk.Key)
					v, ok := key.Get("typed-field")
					if !assert.True(t, ok, `key.Get() should succeed`) {
						return
					}
					field, err := tc.PostProcess(t, v)
					if !assert.NoError(t, err, `tc.PostProcess should succeed`) {
						return
					}

					if !assert.Equal(t, field, expected, `field should match expected value`) {
						return
					}
				}
			})
		}
	})
}

func TestGH412(t *testing.T) {
	base := jwk.NewSet()

	const max = 5
	kids := make(map[string]struct{})
	for i := 0; i < max; i++ {
		k, err := jwxtest.GenerateRsaJwk()
		if !assert.NoError(t, err, `jwxttest.GenerateRsaJwk() should succeed`) {
			return
		}

		kid := "key-" + strconv.Itoa(i)
		k.Set(jwk.KeyIDKey, kid)
		base.AddKey(k)
		kids[kid] = struct{}{}
	}

	for i := 0; i < max; i++ {
		idx := i
		currentKid := "key-" + strconv.Itoa(i)
		t.Run(fmt.Sprintf("Remove at position %d", i), func(t *testing.T) {
			set, err := base.Clone()
			if !assert.NoError(t, err, `base.Clone() should succeed`) {
				return
			}

			if !assert.Equal(t, max, set.Len(), `set.Len should be %d`, max) {
				return
			}

			k, ok := set.Key(idx)
			if !assert.True(t, ok, `set.Get should succeed`) {
				return
			}

			if !assert.NoError(t, set.RemoveKey(k), `set.Remove should succeed`) {
				return
			}
			t.Logf("deleted key %s", k.KeyID())

			if !assert.Equal(t, max-1, set.Len(), `set.Len should be %d`, max-1) {
				return
			}

			expected := make(map[string]struct{})
			for k := range kids {
				if k == currentKid {
					continue
				}
				expected[k] = struct{}{}
			}

			ctx := context.Background()
			for iter := set.Keys(ctx); iter.Next(ctx); {
				pair := iter.Pair()
				key := pair.Value.(jwk.Key)
				if !assert.NotEqual(t, k.KeyID(), key.KeyID(), `key id should not match`) {
					return
				}
				t.Logf("%s found", key.KeyID())
				delete(expected, key.KeyID())
			}

			if !assert.Len(t, expected, 0, `expected map should be empty`) {
				return
			}
		})
	}
}

func TestGH491(t *testing.T) {
	msg := `{"keys":[{"alg":"ECMR","crv":"P-521","key_ops":["deriveKey"],"kty":"EC","x":"AEFldixpd6xWI1rPigk_i_fW_9SLXh3q3h_CbmRIJ2vmnneWnfylvg37q9_BeSxhLpTQkq580tP-7QiOoNem4ubg","y":"AD8MroFIWQI4nm1rVKOb0ImO0Y7EzPt1HTQfZxagv2IoMez8H_vV7Ra9fU7lJhoe3v-Th6x3-4540FodeIxxiphn"},{"alg":"ES512","crv":"P-521","key_ops":["verify"],"kty":"EC","x":"AFZApUzXzvjVJCZQX1De3LUudI7fiWZcZS3t4F2yrxn0tItCYIZrfygPiCZfV1hVKa3WuH2YMrISZUPrSgi_RN2d","y":"ASEyw-_9xcwNBnvpT7thmAF5qHv9-UPYf38AC7y5QBVejQH_DO1xpKzlTbrHCz0jrMeEir8TyW5ywZIYnqGzPBpn"}]}`
	keys, err := jwk.Parse([]byte(msg))
	if !assert.NoError(t, err, `jwk.Parse should succeed`) {
		return
	}

	// there should be 2 keys , get the first key
	k, _ := keys.Key(0)
	ops := k.KeyOps()
	if !assert.Equal(t, jwk.KeyOperationList{jwk.KeyOpDeriveKey}, ops, `k.KeyOps should match`) {
		return
	}
}

func TestSetWithPrivateParams(t *testing.T) {
	k1, err := jwxtest.GenerateRsaJwk()
	if !assert.NoError(t, err, `jwxtest.GenerateRsaJwk should succeed`) {
		return
	}
	k2, err := jwxtest.GenerateEcdsaJwk()
	if !assert.NoError(t, err, `jwxtest.GenerateEcdsaJwk should succeed`) {
		return
	}
	k3, err := jwxtest.GenerateSymmetricJwk()
	if !assert.NoError(t, err, `jwxtest.GenerateSymmetricJwk should succeed`) {
		return
	}

	t.Run("JWK instead of JWKS", func(t *testing.T) {
		var buf bytes.Buffer
		_ = k1.Set(`renewal_kid`, "foo")
		_ = json.NewEncoder(&buf).Encode(k1)

		var check = func(t *testing.T, buf []byte) {
			set, err := jwk.Parse(buf)
			if !assert.NoError(t, err, `jwk.Parse should succeed`) {
				return
			}

			if !assert.Equal(t, 1, set.Len(), `set.Len() should be 1`) {
				return
			}

			v, ok := set.Get(`renewal_kid`)
			if !assert.True(t, ok, `set.Get("renewal_kid") should return ok = true`) {
				return
			}

			if !assert.Equal(t, `foo`, v, `set.Get("renewal_kid") should return "foo"`) {
				return
			}

			key, ok := set.Key(0)
			if !assert.True(t, ok, `set.Key(0) should return ok = true`) {
				return
			}

			v, ok = key.Get(`renewal_kid`)
			if !assert.True(t, ok, `key.Get("renewal_kid") should return ok = true`) {
				return
			}

			if !assert.Equal(t, `foo`, v, `key.Get("renewal_kid") should return "foo"`) {
				return
			}
		}

		t.Run("Check original buffer", func(t *testing.T) {
			check(t, buf.Bytes())
		})
		t.Run("Check serialized", func(t *testing.T) {
			set, err := jwk.Parse(buf.Bytes())
			if !assert.NoError(t, err, `jwk.Parse should succeed`) {
				return
			}
			js, err := json.MarshalIndent(set, "", "  ")
			if !assert.NoError(t, err, `json.MarshalIndent should succeed`) {
				return
			}
			check(t, js)
		})
	})
	t.Run("JWKS with multiple keys", func(t *testing.T) {
		var buf bytes.Buffer
		buf.WriteString(`{"renewal_kid":"foo","keys":[`)
		enc := json.NewEncoder(&buf)
		_ = enc.Encode(k1)
		buf.WriteByte(',')
		_ = enc.Encode(k2)
		buf.WriteByte(',')
		_ = enc.Encode(k3)
		buf.WriteString(`]}`)

		var check = func(t *testing.T, buf []byte) {
			set, err := jwk.Parse(buf)
			if !assert.NoError(t, err, `jwk.Parse should succeed`) {
				return
			}

			if !assert.Equal(t, 3, set.Len(), `set.Len() should be 3`) {
				return
			}

			v, ok := set.Get(`renewal_kid`)
			if !assert.True(t, ok, `set.Get("renewal_kid") should return ok = true`) {
				return
			}

			if !assert.Equal(t, `foo`, v, `set.Get("renewal_kid") should return "foo"`) {
				return
			}
		}

		t.Run("Check original buffer", func(t *testing.T) {
			check(t, buf.Bytes())
		})
		t.Run("Check serialized", func(t *testing.T) {
			set, err := jwk.Parse(buf.Bytes())
			if !assert.NoError(t, err, `jwk.Parse should succeed`) {
				return
			}
			js, err := json.MarshalIndent(set, "", "  ")
			if !assert.NoError(t, err, `json.MarshalIndent should succeed`) {
				return
			}
			check(t, js)
		})
	})
	t.Run("Set private parameters", func(t *testing.T) {
		set := jwk.NewSet()
		if !assert.NoError(t, set.Set(`renewal_kid`, `foo`), `set.Set should succeed`) {
			return
		}

		v, ok := set.Get(`renewal_kid`)
		if !assert.True(t, ok, `set.Get("renewal_kid") should succeed`) {
			return
		}

		if !assert.Equal(t, `foo`, v, `set.Get("renewal_kid") should return "foo"`) {
			return
		}

		if !assert.Error(t, set.Set(`keys`, []string{"foo"}), `set.Set should fail`) {
			return
		}

		k, err := jwk.FromRaw([]byte("foobar"))
		if !assert.NoError(t, err, `jwk.FromRaw should succeed`) {
			return
		}
		keys := []jwk.Key{k}

		if !assert.NoError(t, set.Set(`keys`, keys), `set.Set should succeed`) {
			return
		}

		if !assert.Equal(t, set.Len(), 1, `set should have 1 key`) {
			return
		}
	})
}

func TestFetch(t *testing.T) {
	k1, err := jwxtest.GenerateRsaJwk()
	if !assert.NoError(t, err, `jwxtest.GenerateRsaJwk should succeed`) {
		return
	}
	k2, err := jwxtest.GenerateEcdsaJwk()
	if !assert.NoError(t, err, `jwxtest.GenerateEcdsaJwk should succeed`) {
		return
	}
	k3, err := jwxtest.GenerateSymmetricJwk()
	if !assert.NoError(t, err, `jwxtest.GenerateSymmetricJwk should succeed`) {
		return
	}
	set := jwk.NewSet()
	set.AddKey(k1)
	set.AddKey(k2)
	set.AddKey(k3)

	expected, err := json.MarshalIndent(set, "", "  ")
	if !assert.NoError(t, err, `json.MarshalIndent should succeed`) {
		return
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(expected)
	}))
	defer srv.Close()

	testcases := []struct {
		Name      string
		Whitelist func() jwk.Whitelist
		Error     bool
	}{
		{
			Name: `InsecureWhitelist`,
			Whitelist: func() jwk.Whitelist {
				return jwk.InsecureWhitelist{}
			},
		},
		{
			Name:  `MapWhitelist`,
			Error: true,
			Whitelist: func() jwk.Whitelist {
				return jwk.NewMapWhitelist().
					Add(`https://www.googleapis.com/oauth2/v3/certs`).
					Add(srv.URL)
			},
		},
		{
			Name:  `RegexpWhitelist`,
			Error: true,
			Whitelist: func() jwk.Whitelist {
				return jwk.NewRegexpWhitelist().
					Add(regexp.MustCompile(regexp.QuoteMeta(srv.URL)))
			},
		},
		{
			Name:  `WhitelistFunc`,
			Error: true,
			Whitelist: func() jwk.Whitelist {
				return jwk.WhitelistFunc(func(s string) bool {
					return s == srv.URL
				})
			},
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			wl := tc.Whitelist()

			_, err = jwk.Fetch(ctx, `https://github.com/lestrrat-go/jwx/`, jwk.WithFetchWhitelist(wl))
			if tc.Error {
				if !assert.Error(t, err, `jwk.Fetch should fail`) {
					return
				}
				if !assert.True(t, strings.Contains(err.Error(), `rejected by whitelist`), `error should be whitelist error`) {
					t.Logf("error was %q", err.Error())
					return
				}
			}

			fetched, err := jwk.Fetch(ctx, srv.URL, jwk.WithFetchWhitelist(wl))
			if !assert.NoError(t, err, `jwk.Fetch should succeed`) {
				return
			}

			got, err := json.MarshalIndent(fetched, "", "  ")
			if !assert.NoError(t, err, `json.MarshalIndent should succeed`) {
				return
			}

			if !assert.Equal(t, expected, got, `data should match`) {
				return
			}
		})
	}
}

func TestGH567(t *testing.T) {
	const src = `{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "20595A4BE9F566771792BC3DBC7DF78FF9C36575",
      "x5t": "20595A4BE9F566771792BC3DBC7DF78FF9C36575",
      "e": "AQAB",
      "n": "tAN2xCfMuGpZukiGJl_-aQi_HGd4voyEwuOyL79wZphgtAmMAeOEO9QgxSX00ZczonlOm_I1Xpv2RVnNzSiHfB0bTqn4bLt15JVCBhE1vXaRf63QXn5oZ38fxm_aNctfnmkf65sF3lSzcZmfp1934L1KxJObq4BEOpIxvj00gIOpZQ4Mqw1khfsLhIVeXh8xtiEJwQZPdwIUQD03Yt5XQ_QU3NhxmyXiG8c6auOstdZybbGw10uJQEN4PrW0ESvp_GMnLssYrq6x9PhyvJhZhMFX3rBsYhOI7ILMaqo-QeDYUo0lQ1ENoQFyvtWrNQ_6A-CbmJvL9HdN6AuMkujtUmZzEfbT-k3FRyaZL0JE4-yQikdPGHVK6Q2Ho_Zggx2OTNmLbEORBHNe8cbb7t_5fmK6Fk4TpW3795PR8dG-v-AUGpQEgipg5j-3ONxefyBVZyWyjXaxrhQk6nCeRKcXJ0dKiZQX6ykYrtkgwE3mlcuw9-WzUqvHVEMZgAqBhBhL",
      "x5c": [
        "MIIGpDCCBYygAwIBAgIEX5xBDDANBgkqhkiG9w0BAQsFADBJMQswCQYDVQQGEwJESzESMBAGA1UECgwJVFJVU1QyNDA4MSYwJAYDVQQDDB1UUlVTVDI0MDggU3lzdGVtdGVzdCBYWFhJViBDQTAeFw0yMTA0MjYxMjI1NDBaFw0yNDA0MjYxMTM5NDBaMIGNMQswCQYDVQQGEwJESzEsMCoGA1UECgwjU0lHTkFUVVJHUlVQUEVOIEEvUyAvLyBDVlI6Mjk5MTU5MzgxUDAgBgNVBAUTGUNWUjoyOTkxNTkzOC1VSUQ6NTk5MTEyMjcwLAYDVQQDDCVTSUdOQVRVUkdSVVBQRU4gQS9TIC0gTkVCIFRyYW5zYWN0IFBQMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAtAN2xCfMuGpZukiGJl/\u002BaQi/HGd4voyEwuOyL79wZphgtAmMAeOEO9QgxSX00ZczonlOm/I1Xpv2RVnNzSiHfB0bTqn4bLt15JVCBhE1vXaRf63QXn5oZ38fxm/aNctfnmkf65sF3lSzcZmfp1934L1KxJObq4BEOpIxvj00gIOpZQ4Mqw1khfsLhIVeXh8xtiEJwQZPdwIUQD03Yt5XQ/QU3NhxmyXiG8c6auOstdZybbGw10uJQEN4PrW0ESvp/GMnLssYrq6x9PhyvJhZhMFX3rBsYhOI7ILMaqo\u002BQeDYUo0lQ1ENoQFyvtWrNQ/6A\u002BCbmJvL9HdN6AuMkujtUmZzEfbT\u002Bk3FRyaZL0JE4\u002ByQikdPGHVK6Q2Ho/Zggx2OTNmLbEORBHNe8cbb7t/5fmK6Fk4TpW3795PR8dG\u002Bv\u002BAUGpQEgipg5j\u002B3ONxefyBVZyWyjXaxrhQk6nCeRKcXJ0dKiZQX6ykYrtkgwE3mlcuw9\u002BWzUqvHVEMZgAqBhBhLAgMBAAGjggLNMIICyTAOBgNVHQ8BAf8EBAMCA7gwgZcGCCsGAQUFBwEBBIGKMIGHMDwGCCsGAQUFBzABhjBodHRwOi8vb2NzcC5zeXN0ZW10ZXN0MzQudHJ1c3QyNDA4LmNvbS9yZXNwb25kZXIwRwYIKwYBBQUHMAKGO2h0dHA6Ly92LmFpYS5zeXN0ZW10ZXN0MzQudHJ1c3QyNDA4LmNvbS9zeXN0ZW10ZXN0MzQtY2EuY2VyMIIBIAYDVR0gBIIBFzCCARMwggEPBg0rBgEEAYH0UQIEBgMFMIH9MC8GCCsGAQUFBwIBFiNodHRwOi8vd3d3LnRydXN0MjQwOC5jb20vcmVwb3NpdG9yeTCByQYIKwYBBQUHAgIwgbwwDBYFRGFuSUQwAwIBARqBq0RhbklEIHRlc3QgY2VydGlmaWthdGVyIGZyYSBkZW5uZSBDQSB1ZHN0ZWRlcyB1bmRlciBPSUQgMS4zLjYuMS40LjEuMzEzMTMuMi40LjYuMy41LiBEYW5JRCB0ZXN0IGNlcnRpZmljYXRlcyBmcm9tIHRoaXMgQ0EgYXJlIGlzc3VlZCB1bmRlciBPSUQgMS4zLjYuMS40LjEuMzEzMTMuMi40LjYuMy41LjCBrQYDVR0fBIGlMIGiMDygOqA4hjZodHRwOi8vY3JsLnN5c3RlbXRlc3QzNC50cnVzdDI0MDguY29tL3N5c3RlbXRlc3QzNC5jcmwwYqBgoF6kXDBaMQswCQYDVQQGEwJESzESMBAGA1UECgwJVFJVU1QyNDA4MSYwJAYDVQQDDB1UUlVTVDI0MDggU3lzdGVtdGVzdCBYWFhJViBDQTEPMA0GA1UEAwwGQ1JMMTUwMB8GA1UdIwQYMBaAFM1saJc5chmkNatk6vQRo4GH\u002BGk7MB0GA1UdDgQWBBSJJABtTjZRzzFHsb1JwED0qCo49TAJBgNVHRMEAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQA2yBdGVPbKoYUYRZj4bHLj5Xwqk/yh6sodxwAPYrwxkJBzUKFAwUCTCigpwq8NE00kp3xhFT7Hz/9Z7aZLV4N/D94tc0qDU0JIwlbkrn/i3wx8N8UXf242WVaunJLdKqGtV4ijqjZFGa68XBc3elGjnAMY8eoF56dGg35Ps8Cw2BZyG2aXyEQNs6JYUNzp57\u002B6lJWl0T9Zniaut7Aw2rCII8XRe9WY\u002BHIQX6GuBSw0Q4v9wAfyYftnoULsgfVklkxtQI4kAO5rG17Z5NJuvRkXJD8jp\u002B2jRzcaD8Ud\u002Bpe4keTvuJZ\u002BRj\u002BBDLn/3\u002ByPbs3arD3CIO\u002BlW3Nndr34Le/s"
      ],
      "alg": "RS256"
    },
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "048058BB59F4D3007045896FD488CE81F4EB4923",
      "x5t": "048058BB59F4D3007045896FD488CE81F4EB4923",
      "e": "AQAB",
      "n": "4bOwMSWoWqOSJoLvwFOCVrKmIO_XX5BCI8KYDIgWjII3a83vwia0a11UHm3B6oPlR3L5udworbH7axrmnPz4GEamQp57Yf0uhnGctlVpVVZHOvXPaMlZgTTGhWpJAGnLnyihZbARgyJefuxZ6ZIqeNyjgc_fC-0J7RWFMxNKS_n6ZKFqQlIlmJInJPWR-YZTuooIb4T4C0JAwFDEvXiAs_fX34Tj1FvD1nv01VPGF5Wx6cBV6fejbRCjY4uFfovhE-dtKX0IakZI8jks-uqMjIOB2x1pOuaqrmrINrTYzKTCKrnMpfaW4urhFmQRKNIgaoLnPgzIb3W9F-vpgrdTjw",
      "x5c": [
        "MIID/DCCAeSgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBBMQswCQYDVQQGEwJESzEyMDAGA1UEAxMpTmV0cyBlSUQgQnJva2VyIFRva2VuIFNpZ25pbmcgUm9vdCBQUCBFbnYwHhcNMjEwMjI0MDAwMDAwWhcNNDEwMjI0MDAwMDAwWjA\u002BMQswCQYDVQQGEwJESzEvMC0GA1UEAxMmTmV0cyBlSUQgQnJva2VyIFRva2VuIFNpZ25pbmcgMSBQUCBFbnYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDhs7AxJahao5Imgu/AU4JWsqYg79dfkEIjwpgMiBaMgjdrze/CJrRrXVQebcHqg\u002BVHcvm53CitsftrGuac/PgYRqZCnnth/S6GcZy2VWlVVkc69c9oyVmBNMaFakkAacufKKFlsBGDIl5\u002B7Fnpkip43KOBz98L7QntFYUzE0pL\u002BfpkoWpCUiWYkick9ZH5hlO6ighvhPgLQkDAUMS9eICz99ffhOPUW8PWe/TVU8YXlbHpwFXp96NtEKNji4V\u002Bi\u002BET520pfQhqRkjyOSz66oyMg4HbHWk65qquasg2tNjMpMIqucyl9pbi6uEWZBEo0iBqguc\u002BDMhvdb0X6\u002BmCt1OPAgMBAAGjAjAAMA0GCSqGSIb3DQEBCwUAA4ICAQAFKs2PbOIHLgLTNPIhqKCv7Uj\u002Buj0tpF6vO7CFtw1Q0NKo0UB4wD0T9AYu\u002B8sq3M\u002BZjR77eHP6IkvVBEaqBrZgjq6wU1pijPuIUliXF772\u002B/Hr8Wa23iILWevk\u002BleOXDI8kN7E1JPfr0ADsnCJxaXApDqE6Mysd68\u002BGN2adRuvGAcEcKauVfYLAGPQVctkmQSH6VhIJoDKni7gFF/oMZUZ362sOguhlYltcNUMIILJZkFkksRRriHOlz4I8HJiTzWI1Ufuw6iqFWMquOR4BsQZzBSsdPVGlQvjyqOiBia7rPTJE1Z3Kj0mujIbgKTri8YsnFsBynyHq8puYWvMwoGLWu0goxq9rFrINTe39/YpRE6lZUUZU50DddS\u002B0syBTs1H1gX00ofqt6FgWmACc20zJZm2GyhWDtqtiMurn5WKLoZBQrwN5/a6c6HNCStSVxn8o0g9xCgmWM855S8TqHFYXKJSMG00xZZEbsOAPqujkbKakhC/kJQU7XKGjFRskQZhHvpGipFTK4ZapHYYoo5KqZTytAvFENIcuibIk0u8zlCZuXU/PsowMN4G54FftVVyNHuj4TqiKIvB\u002BZNj/zcPopQHHUISVRApR6YO6fqwPxVaJmSTzZ/0uPTaAdnMz5j1wIYf\u002BZDk1ywTxOBRS7/FwNnWAyIuYGFzewY4H2QUNg=="
      ],
      "alg": "RS256"
    },
    {
      "kty": "RSA",
      "use": "enc",
      "kid": "A2E10A6BAF4E43E86273F57F218A44B824203176",
      "x5t": "A2E10A6BAF4E43E86273F57F218A44B824203176",
      "x5c": [
        "MIIDGjCCAgKgAwIBAgIIQFkx7rDLvyowDQYJKoZIhvcNAQELBQAwNDEyMDAGA1UEAxMpTmV0cyBlSUQgQnJva2VyIGNsaWVudCByZXF1ZXN0IGVuY3J5cHRpb24wIBcNMjIwMjA5MTQxMDQ1WhgPMjExMjAyMTAxNDEwNDVaMDQxMjAwBgNVBAMTKU5ldHMgZUlEIEJyb2tlciBjbGllbnQgcmVxdWVzdCBlbmNyeXB0aW9uMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAps2R1sxEGxyYfP\u002BK2jq4uDONxrEP4W4oAKJkTv71oOJiK3CBK4ybyk597WufUZfpy8isUKtuqx1x6DTK6vnecUv5KV77/ql6Ac8LJaj5zQBRGuPoPezbD2tPglxp4XEU\u002BqivoyMJiZoLl75MklxvmVVlJQgu1H4RmvdCcp0xYmV2CBX4GKvK6g26y3IZ1FW4Vj5G8eB\u002Bxw423EtsBO3iKPx24BbVZWXC56lhke\u002BQbpbagU/hpQnOdW5tdWdm7oHGUfGwsvg1f6b2Yllwv57ANJkk\u002BfBr\u002BoN0eD2DRNyHbExzJfOBPkDt2FEq1u30kfLP\u002B6ecSByaxSFTl\u002BgFeUUw0wIDAQABoy4wLDALBgNVHQ8EBAMCBBAwHQYDVR0OBBYEFPK08YkmSYK1xNIFEr1AdscfYKnZMA0GCSqGSIb3DQEBCwUAA4IBAQAYeP7IAv3ND\u002B6UMGr9X\u002BP1wURz7UQd66oRldhcdkdS\u002BBNMcU/gVeiU31Es5Y/GhdmKPiuQGdIQdPO88u9A7STWIYUj/lnrgtKif\u002BJ8V/PtfsvHbBYD5f7wFd7fqOpcDFQ2dobOathhrqJ1r3ShFaObpVBX3PL3\u002BSFK3ofHaMYWuIoD\u002BroiOJfIYlL02rrKiiw9r2L9nUCZfSAq3G9rMw\u002BzL38D9BQvrEe9yvwqM3im0m3seiNODiArcY/ee\u002B538\u002BYaToaMPHxUAizREeJFm4aOtwzGND48XHQzbNyfhoSsJesCJsugcNfHUe6o0nuPZ\u002BzvdLrboutrrtxEN8yOm489"
      ],
      "alg": "http://www.w3.org/2001/04/xmlenc#rsa-oaep"
    }
  ]
}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set(`Content-Type`, `application/json`)
		w.WriteHeader(http.StatusOK)

		io.WriteString(w, src)
	}))
	defer srv.Close()

	for _, ignoreParseError := range []bool{true, false} {
		ignoreParseError := ignoreParseError
		t.Run(fmt.Sprintf(`Parse with ignoreParseError=%t`, ignoreParseError), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			c := jwk.NewCache(ctx)
			c.Register(srv.URL, jwk.WithIgnoreParseError(ignoreParseError))

			set, err := c.Get(ctx, srv.URL)
			if ignoreParseError {
				if !assert.NoError(t, err, `ar.Fetch should succeed`) {
					return
				}
				if !assert.Equal(t, set.Len(), 2, `JWKS should contain two keys`) {
					return
				}
			} else {
				if !assert.Error(t, err, `ar.Fetch should fail`) {
					return
				}
			}
		})
	}

	// Test the case when WithIgnoreParseError is passed to ParseKey
	t.Run(`ParseKey + WithIgnoreParseError should be an error`, func(t *testing.T) {
		key, err := jwxtest.GenerateRsaJwk()
		if !assert.NoError(t, err, `jwxtest.GenerateRsaJwk() should succeed`) {
			return
		}

		buf, err := json.Marshal(key)
		if !assert.NoError(t, err, `json.Marshal should succeed`) {
			return
		}

		_, err = jwk.ParseKey(buf)
		if !assert.NoError(t, err, `jwk.ParseKey (no WithIgnoreParseError) should succeed`) {
			return
		}

		_, err = jwk.ParseKey(buf, jwk.WithIgnoreParseError(true))
		if !assert.Error(t, err, `jwk.ParseKey (no WithIgnoreParseError) should fail`) {
			return
		}
	})
}

func TestAvailableCurves(t *testing.T) {
	// Not much to test here, but this silences the linters
	_ = jwk.AvailableCurves()
}

func TestCurveForAlgorithm(t *testing.T) {
	// Not much to test here, but this silences the linters
	_, _ = jwk.CurveForAlgorithm(jwa.P521)
}

func TestGH664(t *testing.T) {
	privkey, err := jwxtest.GenerateRsaKey()
	if !assert.NoError(t, err, `jwxtext.GenerateRsaKey() should succeed`) {
		return
	}

	// first, test a stupid case where Primes > 2
	privkey.Primes = append(privkey.Primes, &big.Int{})
	_, err = jwk.FromRaw(privkey)
	if !assert.Error(t, err, `jwk.FromRaw should fail`) {
		return
	}

	privkey.Primes = privkey.Primes[:2]

	// nuke p and q, dp, dq, qi
	for i := 0; i < 3; i++ {
		i := i
		t.Run(fmt.Sprintf("Check what happens when primes are reduced to %d", i), func(t *testing.T) {
			privkey.Primes = privkey.Primes[:i]
			privkey.Precomputed.Dp = nil
			privkey.Precomputed.Dq = nil
			privkey.Precomputed.Qinv = nil
			privkey.Precomputed.CRTValues = nil

			jwkPrivkey, err := jwk.FromRaw(privkey)
			if !assert.NoError(t, err, `jwk.FromRaw should succeed`) {
				return
			}

			buf, _ := json.MarshalIndent(jwkPrivkey, "", "  ")
			parsed, err := jwk.ParseKey(buf)
			if !assert.NoError(t, err, `jwk.ParseKey should succeed`) {
				return
			}

			payload := []byte(`hello , world!`)
			signed, err := jws.Sign(payload, jws.WithKey(jwa.RS256, parsed))
			if !assert.NoError(t, err, `jws.Sign should succeed`) {
				return
			}

			verified, err := jws.Verify(signed, jws.WithKey(jwa.RS256, privkey.PublicKey))
			if !assert.NoError(t, err, `jws.Verify should succeed`) {
				return
			}

			if !assert.Equal(t, payload, verified, `verified content should match`) {
				return
			}
		})
	}
}

func TestGH730(t *testing.T) {
	key, err := jwk.FromRaw([]byte(`abracadabra`))
	require.NoError(t, err, `jwk.FromRaw should succeed`)
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(key), `first AddKey should succeed`)
	require.Error(t, set.AddKey(key), `second AddKey should fail`)
}

// This test was lifted from #875. See tests under Roundtrip/WithPEM(true) for other key types
func TestECDSAPEM(t *testing.T) {
	// go make an EC key at https://mkjwk.org/
	key, err := jwk.ParseKey([]byte(`{
		"kty": "EC",
		"d": "zqYPTs5gMEwtidOqjlFJSk6L4BQSfhCJX6FTgbuuiE0",
		"crv": "P-256",
		"x": "AYwhwiE1hXWdfwu-HlBSsY5Chxycu-LyE6WsZ_w2DO4",
		"y": "zumemGclMFkimMsKMXlLdKYWtLle58e4N9hDPcN7lig"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	pem, err := jwk.EncodePEM(key)
	if err != nil {
		t.Fatal(err)
	}
	_, err = jwk.ParseKey(pem, jwk.WithPEM(true))
	if err != nil {
		t.Fatal(err)
	}
}
