package jwk_test

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/cert"
	"github.com/lestrrat-go/jwx/v4/internal/base64"
	"github.com/lestrrat-go/jwx/v4/internal/jose"
	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/lestrrat-go/jwx/v4/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v4/internal/tokens"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	ourecdsa "github.com/lestrrat-go/jwx/v4/jwk/ecdsa"
	"github.com/stretchr/testify/require"
)

var zeroval reflect.Value
var certChain *cert.Chain
var certChainSrc = []string{
	"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",
}

type keyDef struct {
	Expected any
	Value    any
	Method   string
}

var commonDef map[string]keyDef

func init() {
	jwa.RegisterSignatureAlgorithm(jwa.NewSignatureAlgorithm("ECMR"))

	certChain = &cert.Chain{}
	for _, src := range certChainSrc {
		_ = certChain.AddString(src)
	}

	alg, ok := jwa.LookupSignatureAlgorithm("RS256")
	if !ok {
		panic("failed to find RS256 algorithm")
	}

	commonDef = map[string]keyDef{
		jwk.AlgorithmKey: {
			Method: "Algorithm",
			Value:  alg,
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
			Value:  "http://github.com/lestrrat-go/jwx/v4",
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
	data := map[string]any{}
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

func expectedRawKeyType(key jwk.Key) any {
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
		crv, ok := key.Crv()
		if !ok {
			panic("missing crv")
		}
		switch crv {
		case jwa.Ed25519():
			return ed25519.PrivateKey(nil)
		case jwa.X25519():
			return &ecdh.PrivateKey{}
		default:
			panic("unknown curve type for OKPPrivateKey:" + crv.String())
		}
	case jwk.OKPPublicKey:
		crv, ok := key.Crv()
		if !ok {
			panic("missing crv")
		}
		switch crv {
		case jwa.Ed25519():
			return ed25519.PublicKey(nil)
		case jwa.X25519():
			return &ecdh.PublicKey{}
		default:
			panic("unknown curve type for OKPPublicKey:" + crv.String())
		}
	default:
		panic(fmt.Sprintf("unknown key type: %T", key))
	}
}

func VerifyKey(t *testing.T, def map[string]keyDef) {
	t.Helper()

	def = complimentDef(def)
	key, err := jwk.ParseKey[jwk.Key](makeKeyJSON(def))
	require.NoError(t, err, `jwk.ParseKey should succeed`)

	t.Run("Fields", func(t *testing.T) {
		for k, kdef := range def {
			t.Run(k, func(t *testing.T) {
				getval, ok := key.Field(k)
				require.True(t, ok, `key.Field(%s) should succeed`, k)

				expected := kdef.Expected
				if expected == nil {
					expected = kdef.Value
				}
				require.Equal(t, expected, getval)

				if mname := kdef.Method; mname != "" {
					method := reflect.ValueOf(key).MethodByName(mname)
					require.NotEqual(t, zeroval, method, `method should not be a zero value`)
					retvals := method.Call(nil)

					expectedReturnValues := 2
					if mname == "KeyType" {
						expectedReturnValues = 1
					}
					require.Len(t, retvals, expectedReturnValues, `there should be 1 return value`)
					require.Equal(t, expected, retvals[0].Interface())
				}
			})
		}
	})
	t.Run("Roundtrip", func(t *testing.T) {
		var supportsPEM bool
		switch key.KeyType() {
		case jwa.OKP(), jwa.OctetSeq():
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
					require.NoError(t, err, `jwk.EncodePEM should succeed`)
					buf = pem
				} else {
					jsonbuf, err := json.Marshal(key)
					require.NoError(t, err, `json.Marshal should succeed`)
					buf = jsonbuf
					t.Logf("%s", buf)
				}

				newkey, err := jwk.ParseKey[jwk.Key](buf, jwk.WithPEM(usePEM))
				require.NoError(t, err, `jwk.ParseKey should succeed`)
			LOOP:
				for _, k := range key.Keys() {
					if usePEM {
						switch k {
						case `private`, jwk.AlgorithmKey, jwk.KeyIDKey, jwk.KeyOpsKey, jwk.KeyUsageKey, jwk.X509CertChainKey, jwk.X509CertThumbprintKey, jwk.X509CertThumbprintS256Key, jwk.X509URLKey:
							continue LOOP
						}
					}

					v, ok := key.Field(k)
					require.True(t, ok, `key.Field(%s) should succeed`, k)
					v2, ok := newkey.Field(k)
					require.True(t, ok, `newkey.Field(%s) should succeed`, k)
					require.Equal(t, v, v2, `values should match`)
				}
			})
		}
	})
	t.Run("Raw", func(t *testing.T) {
		typ := expectedRawKeyType(key)

		rawkey, err := jwk.Export[any](key)
		require.NoError(t, err, `Raw() should succeed`)
		require.IsType(t, rawkey, typ, `raw key should be of this type`)
	})
	t.Run("PublicKey", func(t *testing.T) {
		_, err := jwk.PublicKeyOf(key)
		require.NoError(t, err, `jwk.PublicKeyOf should succeed`)
	})
	t.Run("IsPrivate", func(t *testing.T) {
		_, err := jwk.IsPrivateKey(key)
		if _, ok := key.(jwk.SymmetricKey); ok {
			require.Error(t, err, `jwk.IsPrivateKey should fail`)
		} else {
			require.NoError(t, err, `jwk.IsPrivateKey should succeed`)
		}
	})
	t.Run("Set/Remove", func(t *testing.T) {
		newkey, err := key.Clone()
		require.NoError(t, err, `key.Clone should succeed`)
		for _, k := range key.Keys() {
			require.NoError(t, newkey.Remove(k), `newkey.Remove should succeed`)
		}

		for _, k := range newkey.Keys() {
			require.Equal(t, k, jwk.KeyTypeKey, `key should be kty`)
		}

		for _, k := range key.Keys() {
			v, ok := key.Field(k)
			require.True(t, ok, `key.Field should succeed`)
			require.NoError(t, newkey.Set(k, v), `newkey.Set should succeed`)
		}
	})
}

func TestNew(t *testing.T) {
	t.Parallel()
	k, err := jwk.Import[jwk.Key](nil)
	require.Nil(t, k, "key should be nil")
	require.Error(t, err, "nil key should cause an error")
}

func TestGenericImport(t *testing.T) {
	t.Parallel()
	t.Run("RSAPrivateKey", func(t *testing.T) {
		t.Parallel()
		raw, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		key, err := jwk.Import[jwk.RSAPrivateKey](raw)
		require.NoError(t, err)
		require.NotNil(t, key)
		require.Equal(t, jwa.RSA(), key.KeyType())
	})
	t.Run("ECDSAPublicKey", func(t *testing.T) {
		t.Parallel()
		raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		key, err := jwk.Import[jwk.ECDSAPublicKey](&raw.PublicKey)
		require.NoError(t, err)
		require.NotNil(t, key)
		require.Equal(t, jwa.EC(), key.KeyType())
	})
	t.Run("SymmetricKey", func(t *testing.T) {
		t.Parallel()
		key, err := jwk.Import[jwk.SymmetricKey]([]byte("my-secret"))
		require.NoError(t, err)
		require.NotNil(t, key)
		require.Equal(t, jwa.OctetSeq(), key.KeyType())
	})
	t.Run("OKPPrivateKey", func(t *testing.T) {
		t.Parallel()
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		key, err := jwk.Import[jwk.OKPPrivateKey](priv)
		require.NoError(t, err)
		require.NotNil(t, key)
		require.Equal(t, jwa.OKP(), key.KeyType())
	})
	t.Run("TypeMismatch", func(t *testing.T) {
		t.Parallel()
		// Importing []byte produces SymmetricKey, not RSAPrivateKey
		_, err := jwk.Import[jwk.RSAPrivateKey]([]byte("symmetric"))
		require.Error(t, err)
	})
	t.Run("BaseInterface", func(t *testing.T) {
		t.Parallel()
		// Import[Key] always succeeds for valid input
		key, err := jwk.Import[jwk.Key]([]byte("my-secret"))
		require.NoError(t, err)
		require.NotNil(t, key)
	})
}

const testOctKeyJSON = `{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}`

func TestGenericParseKey(t *testing.T) {
	t.Parallel()
	t.Run("JSON", func(t *testing.T) {
		t.Parallel()
		key, err := jwk.ParseKey[jwk.SymmetricKey]([]byte(testOctKeyJSON))
		require.NoError(t, err)
		require.NotNil(t, key)
		require.Equal(t, jwa.OctetSeq(), key.KeyType())
	})
	t.Run("PEM", func(t *testing.T) {
		t.Parallel()
		raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		derBytes, err := x509.MarshalECPrivateKey(raw)
		require.NoError(t, err)

		pemData := pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: derBytes,
		})
		key, err := jwk.ParseKey[jwk.ECDSAPrivateKey](pemData, jwk.WithPEM(true))
		require.NoError(t, err)
		require.NotNil(t, key)
		require.Equal(t, jwa.EC(), key.KeyType())
	})
	t.Run("TypeMismatch", func(t *testing.T) {
		t.Parallel()
		_, err := jwk.ParseKey[jwk.RSAPrivateKey]([]byte(testOctKeyJSON))
		require.Error(t, err)
	})
	t.Run("BaseInterface", func(t *testing.T) {
		t.Parallel()
		key, err := jwk.ParseKey[jwk.Key]([]byte(testOctKeyJSON))
		require.NoError(t, err)
		require.NotNil(t, key)
	})
	t.Run("ErrorPropagation", func(t *testing.T) {
		t.Parallel()
		_, err := jwk.ParseKey[jwk.Key]([]byte(`not json`))
		require.Error(t, err)
	})
}

func TestParse(t *testing.T) {
	t.Parallel()
	verify := func(t *testing.T, src string, expected reflect.Type) {
		t.Helper()
		t.Run("json.Unmarshal", func(t *testing.T) {
			set := jwk.NewSet()
			err := json.Unmarshal([]byte(src), set)
			require.NoError(t, err, `json.Unmarshal should succeed`)

			require.True(t, set.Len() > 0, "set.Keys should be greater than 0")
			for i := range set.Len() {
				key, err := set.Key(i)
				require.True(t, err, `set.Key(%d) should succeed`, i)
				require.True(t, reflect.TypeOf(key).AssignableTo(expected), "key should be a %s", expected)
			}
		})
		t.Run("jwk.Parse", func(t *testing.T) {
			t.Helper()
			set, err := jwk.Parse([]byte(`{"keys":[` + src + `]}`))
			require.NoError(t, err, `jwk.Parse should succeed`)
			require.True(t, set.Len() > 0, "set.Len should be greater than 0")

			for i := range set.Len() {
				key, ok := set.Key(i)
				require.True(t, ok, `set.Key(%d) should succeed`, i)
				switch key := key.(type) {
				case jwk.RSAPrivateKey, jwk.ECDSAPrivateKey, jwk.OKPPrivateKey, jwk.RSAPublicKey, jwk.ECDSAPublicKey, jwk.OKPPublicKey, jwk.SymmetricKey:
				default:
					require.Fail(t, fmt.Sprintf("invalid type: %T", key))
				}
			}
		})
		t.Run("jwk.ParseKey", func(t *testing.T) {
			t.Helper()
			key, err := jwk.ParseKey[jwk.Key]([]byte(src))
			require.NoError(t, err, `jwk.ParseKey should succeed`)

			t.Run("Raw", func(t *testing.T) {
				t.Helper()

				irawkey, err := jwk.Export[any](key)
				require.NoError(t, err, `jwk.Export should succeed`)

				isPrivate, err := jwk.IsPrivateKey(key)
				require.NoError(t, err, "jwk.IsPrivateKey(%T) should succeed", key)

				var crawkey any
				switch k := key.(type) {
				case jwk.RSAPrivateKey:
					require.True(t, isPrivate, `jwk.IsPrivateKey(&rsa.PrivateKey) should be true`)
					rawkey, ok := irawkey.(*rsa.PrivateKey)
					require.True(t, ok, `key.Raw should return *rsa.PrivateKey`)
					crawkey = rawkey
				case jwk.RSAPublicKey:
					require.False(t, isPrivate, `jwk.IsPrivateKey(&rsa.PublicKey) should be false`)
					rawkey, ok := irawkey.(*rsa.PublicKey)
					require.True(t, ok, `key.Raw should return *rsa.PublicKey`)
					crawkey = rawkey
				case jwk.ECDSAPrivateKey:
					require.True(t, isPrivate, `jwk.IsPrivateKey(&ecdsa.PrivateKey) should be true`)
					rawkey, ok := irawkey.(*ecdsa.PrivateKey)
					require.True(t, ok, `key.Raw should return *ecdsa.PrivateKey`)
					crawkey = rawkey
				case jwk.OKPPrivateKey:
					require.True(t, isPrivate, `jwk.IsPrivateKey(&ed25519.PrivateKey) should be true`)
					crv, ok := k.Crv()
					require.True(t, ok, `k.Crv() should succeed`)
					switch crv {
					case jwa.Ed25519():
						rawkey, ok := irawkey.(ed25519.PrivateKey)
						require.True(t, ok, `key.Raw should return ed25519.PrivateKey`)
						crawkey = rawkey
					case jwa.X25519():
						rawkey, ok := irawkey.(*ecdh.PrivateKey)
						require.True(t, ok, `key.Raw should return *ecdh.PrivateKey`)
						crawkey = rawkey
					default:
						t.Errorf(`invalid curve %s`, crv)
					}
				// NOTE: Has to come after private
				// key, since it's a subset of the
				// private key variant.
				case jwk.OKPPublicKey:
					require.False(t, isPrivate, `jwk.IsPrivateKey(&ed25519.PublicKey) should be false`)
					crv, ok := k.Crv()
					require.True(t, ok, `k.Crv() should succeed`)
					switch crv {
					case jwa.Ed25519():
						rawkey, ok := irawkey.(ed25519.PublicKey)
						require.True(t, ok, `key.Raw should return ed25519.PublicKey`)
						crawkey = rawkey
					case jwa.X25519():
						rawkey, ok := irawkey.(*ecdh.PublicKey)
						require.True(t, ok, `key.Raw should return *ecdh.PublicKey`)
						crawkey = rawkey
					default:
						t.Errorf(`invalid curve %s`, crv)
					}
				default:
					t.Errorf(`invalid key type %T`, key)
					return
				}

				require.IsType(t, crawkey, irawkey, `key types should match`)
			})
		})
		t.Run("ParseRawKey", func(t *testing.T) {
			var v any
			require.NoError(t, jwk.ParseRawKey([]byte(src), &v), `jwk.ParseRawKey should succeed`)
		})
	}

	t.Run("RSA Public Key", func(t *testing.T) {
		t.Parallel()
		const src = `{
      "e":"AQAB",
			"kty":"RSA",
      "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
		}`
		verify(t, src, reflect.TypeFor[jwk.RSAPublicKey]())
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
		verify(t, src, reflect.TypeFor[jwk.RSAPrivateKey]())
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
		verify(t, src, reflect.TypeFor[jwk.ECDSAPrivateKey]())
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
		require.Error(t, err, `jwk.ParseString should fail`)
	})
	t.Run("Ed25519 Public Key", func(t *testing.T) {
		t.Parallel()
		// Key taken from RFC 8037
		const src = `{
		  "kty" : "OKP",
		  "crv" : "Ed25519",
		  "x"   : "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
		}`
		verify(t, src, reflect.TypeFor[jwk.OKPPublicKey]())
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
		verify(t, src, reflect.TypeFor[jwk.OKPPrivateKey]())
	})
	t.Run("X25519 Public Key", func(t *testing.T) {
		t.Parallel()
		// Key taken from RFC 8037
		const src = `{
		  "kty" : "OKP",
		  "crv" : "X25519",
		  "x"   : "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"
		}`
		verify(t, src, reflect.TypeFor[jwk.OKPPublicKey]())
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
		verify(t, src, reflect.TypeFor[jwk.OKPPrivateKey]())
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
		require.NoError(t, err, `tc.generate should succeed`)
		require.NoError(t, ks1.AddKey(key), `ks1.Add should succeed`)
	}

	buf, err := json.MarshalIndent(ks1, "", "  ")
	require.NoError(t, err, "JSON marshal succeeded")

	ks2, err := jwk.Parse(buf)
	require.NoError(t, err, "JSON unmarshal succeeded")

	for _, tc := range tests {
		key1, ok := ks2.LookupKeyID(tc.keyID)
		require.True(t, ok, "ks2.LookupKeyID should succeed")

		key2, ok := ks1.LookupKeyID(tc.keyID)
		require.True(t, ok, "ks1.LookupKeyID should succeed")

		pk1json, _ := json.Marshal(key1)
		pk2json, _ := json.Marshal(key2)
		require.Equal(t, pk1json, pk2json, "Keys should match (kid = %s)", tc.keyID)
	}
}

func TestAccept(t *testing.T) {
	t.Parallel()
	t.Run("KeyOperation", func(t *testing.T) {
		t.Parallel()
		testcases := []struct {
			Args  any
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
				Args: []any{"sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey"},
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
				require.Error(t, ops.Accept(test.Args), `KeyOperationList.Accept should fail`)
			} else {
				require.NoError(t, ops.Accept(test.Args), `KeyOperationList.Accept should succeed`)
			}
		}
	})
	t.Run("KeyUsage", func(t *testing.T) {
		t.Parallel()
		testcases := []struct {
			Args  any
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
				require.Error(t, usage.Accept(test.Args), `KeyUsage.Accept should fail`)
			} else {
				require.NoError(t, usage.Accept(test.Args), `KeyUsage.Accept should succeed`)
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
		require.NoError(t, err, `jwk generation should be successful`)
		kid, ok := k.KeyID()
		require.False(t, ok, `k.KeyID should be empty`)
		require.Empty(t, kid, `k.KeyID should be non-empty`)
		require.NoError(t, jwk.AssignKeyID(k), `AssignKeyID shuld be successful`)
		kid, ok = k.KeyID()
		require.True(t, ok, `k.KeyID should be non-empty`)
		require.NotEmpty(t, kid, `k.KeyID should be non-empty`)
	}
}

func TestPublicKeyOf(t *testing.T) {
	t.Parallel()

	rsakey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err, `generating raw RSA key should succeed`)

	ecdsakey, err := jwxtest.GenerateEcdsaKey(jwa.P521())
	require.NoError(t, err, `generating raw ECDSA key should succeed`)

	octets := jwxtest.GenerateSymmetricKey()

	ed25519key, err := jwxtest.GenerateEd25519Key()
	require.NoError(t, err, `generating raw Ed25519 key should succeed`)

	x25519key, err := jwxtest.GenerateX25519Key()
	require.NoError(t, err, `generating raw X25519 key should succeed`)

	keys := []struct {
		Key           any
		PublicKeyType reflect.Type
	}{
		{
			Key:           rsakey,
			PublicKeyType: reflect.PointerTo(reflect.TypeFor[rsa.PublicKey]()),
		},
		{
			Key:           *rsakey,
			PublicKeyType: reflect.PointerTo(reflect.TypeFor[rsa.PublicKey]()),
		},
		{
			Key:           rsakey.PublicKey,
			PublicKeyType: reflect.PointerTo(reflect.TypeFor[rsa.PublicKey]()),
		},
		{
			Key:           &rsakey.PublicKey,
			PublicKeyType: reflect.PointerTo(reflect.TypeFor[rsa.PublicKey]()),
		},
		{
			Key:           ecdsakey,
			PublicKeyType: reflect.PointerTo(reflect.TypeFor[ecdsa.PublicKey]()),
		},
		{
			Key:           *ecdsakey,
			PublicKeyType: reflect.PointerTo(reflect.TypeFor[ecdsa.PublicKey]()),
		},
		{
			Key:           ecdsakey.PublicKey,
			PublicKeyType: reflect.PointerTo(reflect.TypeFor[ecdsa.PublicKey]()),
		},
		{
			Key:           &ecdsakey.PublicKey,
			PublicKeyType: reflect.PointerTo(reflect.TypeFor[ecdsa.PublicKey]()),
		},
		{
			Key:           octets,
			PublicKeyType: reflect.TypeFor[[]byte](),
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
			PublicKeyType: reflect.TypeFor[*ecdh.PublicKey](),
		},
		{
			Key:           x25519key.Public(),
			PublicKeyType: reflect.TypeFor[*ecdh.PublicKey](),
		},
	}

	for _, key := range keys {
		t.Run(fmt.Sprintf("%T", key.Key), func(t *testing.T) {
			t.Parallel()

			pubkey, err := jwk.PublicRawKeyOf(key.Key)
			require.NoError(t, err, `jwk.PublicKeyOf(%T) should succeed`, key.Key)
			require.Equal(t, key.PublicKeyType, reflect.TypeOf(pubkey), `public key types should match (got %T)`, pubkey)

			// Go through jwk.Import
			jwkKey, err := jwk.Import[jwk.Key](key.Key)
			require.NoError(t, err, `jwk.Import should succeed`)

			pubJwkKey, err := jwk.PublicKeyOf(jwkKey)
			require.NoError(t, err, `jwk.PublicKeyOf(%T) should succeed`, jwkKey)

			// Get the raw key to compare
			rawKey, err := jwk.Export[any](pubJwkKey)
			require.NoError(t, err, `pubJwkKey.Raw should succeed`)
			require.Equal(t, key.PublicKeyType, reflect.TypeOf(rawKey), `public key types should match (got %T)`, rawKey)
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
			jwkKey, err := jwk.Import[jwk.Key](key.Key)
			require.NoError(t, err, `jwk.Import should succeed`)

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
		require.NoError(t, err, `jwk.PublicKeyOf(jwk.Set) should succeed`)

		for i, key := range setKeys {
			setKey, ok := newSet.Key(i)
			require.True(t, ok, `element %d should be present`, i)
			kid, ok := setKey.KeyID()
			require.True(t, ok, `KeyID() should be present`)
			require.Equal(t, fmt.Sprintf("key%d", i), kid, `KeyID() should match for %T`, setKey)

			// Get the raw key to compare
			rawKey, err := jwk.Export[any](setKey)
			require.NoError(t, err, `pubJwkKey.Raw should succeed`)
			require.Equal(t, key.PublicKeyType, reflect.TypeOf(rawKey), `public key types should match (got %T)`, rawKey)
		}
	})
}

func TestPublicSetOfSymmetricRejection(t *testing.T) {
	t.Parallel()

	makeRSA := func(t *testing.T, kid string) jwk.Key {
		t.Helper()
		rawRSA, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err, `rsa.GenerateKey should succeed`)
		k, err := jwk.Import[jwk.Key](rawRSA)
		require.NoError(t, err, `jwk.Import RSA should succeed`)
		require.NoError(t, k.Set(jwk.KeyIDKey, kid), `Set kid should succeed`)
		return k
	}
	makeHMAC := func(t *testing.T, kid string) jwk.Key {
		t.Helper()
		k, err := jwk.Import[jwk.Key]([]byte("top-secret-hmac-material"))
		require.NoError(t, err, `jwk.Import symmetric should succeed`)
		require.NoError(t, k.Set(jwk.KeyIDKey, kid), `Set kid should succeed`)
		return k
	}

	t.Run("mixed set rejects symmetric by default", func(t *testing.T) {
		t.Parallel()
		set := jwk.NewSet()
		require.NoError(t, set.AddKey(makeRSA(t, "rsa-1")))
		require.NoError(t, set.AddKey(makeHMAC(t, "hmac-1")))

		_, err := jwk.PublicSetOf(set)
		require.Error(t, err, `PublicSetOf should reject a set containing a symmetric key`)
		require.ErrorContains(t, err, "symmetric")
		require.ErrorContains(t, err, `"hmac-1"`)
	})

	t.Run("mixed set passes through with WithAllowSymmetric(true)", func(t *testing.T) {
		t.Parallel()
		set := jwk.NewSet()
		require.NoError(t, set.AddKey(makeRSA(t, "rsa-1")))
		require.NoError(t, set.AddKey(makeHMAC(t, "hmac-1")))

		pub, err := jwk.PublicSetOf(set, jwk.WithAllowSymmetric(true))
		require.NoError(t, err, `PublicSetOf with WithAllowSymmetric(true) should succeed`)
		require.Equal(t, 2, pub.Len(), `resulting set should still contain both keys`)

		buf, err := json.Marshal(pub)
		require.NoError(t, err, `json.Marshal should succeed`)
		// Pin the dangerous opt-in behavior: secret material is still present.
		require.Contains(t, string(buf), `"k":`, `opt-in pass-through keeps the secret in the output`)
	})

	t.Run("pure symmetric set rejected by default", func(t *testing.T) {
		t.Parallel()
		set := jwk.NewSet()
		require.NoError(t, set.AddKey(makeHMAC(t, "hmac-only")))

		_, err := jwk.PublicSetOf(set)
		require.Error(t, err, `PublicSetOf should reject a purely symmetric set`)
		require.ErrorContains(t, err, `"hmac-only"`)
	})

	t.Run("empty set succeeds", func(t *testing.T) {
		t.Parallel()
		pub, err := jwk.PublicSetOf(jwk.NewSet())
		require.NoError(t, err, `PublicSetOf on empty set should succeed`)
		require.Equal(t, 0, pub.Len(), `result should be empty`)
	})

	t.Run("pure asymmetric set is unaffected", func(t *testing.T) {
		t.Parallel()
		set := jwk.NewSet()
		require.NoError(t, set.AddKey(makeRSA(t, "rsa-a")))
		require.NoError(t, set.AddKey(makeRSA(t, "rsa-b")))

		pub, err := jwk.PublicSetOf(set)
		require.NoError(t, err, `PublicSetOf on asymmetric-only set should succeed`)
		require.Equal(t, 2, pub.Len())
	})
}

func TestIssue207(t *testing.T) {
	t.Parallel()
	const src = `{"kty":"EC","alg":"ECMR","crv":"P-521","key_ops":["deriveKey"],"x":"AJwCS845x9VljR-fcrN2WMzIJHDYuLmFShhyu8ci14rmi2DMFp8txIvaxG8n7ZcODeKIs1EO4E_Bldm_pxxs8cUn","y":"ASjz754cIQHPJObihPV8D7vVNfjp_nuwP76PtbLwUkqTk9J1mzCDKM3VADEk-Z1tP-DHiwib6If8jxnb_FjNkiLJ"}`

	// Using a loop here because we're using sync.Pool
	// just for sanity.
	for range 10 {
		k, err := jwk.ParseKey[jwk.Key]([]byte(src))
		require.NoError(t, err, `jwk.ParseKey should succeed`)

		thumb, err := k.Thumbprint(crypto.SHA1)
		require.NoError(t, err, `k.Thumbprint should succeed`)
		require.Equal(t, `2Mc_43O_BOrOJTNrGX7uJ6JsIYE`, base64.EncodeToString(thumb), `thumbprints should match`)
	}
}

func TestIssue270(t *testing.T) {
	t.Parallel()
	const src = `{"kty":"EC","alg":"ECMR","crv":"P-521","key_ops":["deriveKey"],"x":"AJwCS845x9VljR-fcrN2WMzIJHDYuLmFShhyu8ci14rmi2DMFp8txIvaxG8n7ZcODeKIs1EO4E_Bldm_pxxs8cUn","y":"ASjz754cIQHPJObihPV8D7vVNfjp_nuwP76PtbLwUkqTk9J1mzCDKM3VADEk-Z1tP-DHiwib6If8jxnb_FjNkiLJ"}`
	k, err := jwk.ParseKey[jwk.Key]([]byte(src))
	require.NoError(t, err, `jwk.ParseKey should succeed`)

	for _, usage := range []string{"sig", "enc"} {
		require.NoError(t, k.Set(jwk.KeyUsageKey, usage))
		require.NoError(t, k.Set(jwk.KeyUsageKey, jwk.KeyUsageType(usage)))
	}
}

func TestReadFile(t *testing.T) {
	t.Parallel()
	if !jose.Available() {
		t.SkipNow()
	}

	ctx := t.Context()

	fn, clean, err := jose.GenerateJwk(ctx, t, `{"alg": "RS256"}`)
	require.NoError(t, err, `jose.GenerateJwk`)

	defer clean()
	_, err = jwk.ParseFS(os.DirFS(filepath.Dir(fn)), filepath.Base(fn))
	require.NoError(t, err, `jwk.ParseFS should succeed`)
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
				Value:  jwa.RSA(),
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
				_, err := jwk.Import[jwk.Key](raw)
				require.Error(t, err, `jwk.Import should fail for invalid key`)
			}
		})
	})
	t.Run("Private Key", func(t *testing.T) {
		t.Parallel()
		VerifyKey(t, map[string]keyDef{
			jwk.KeyTypeKey: {
				Method: "KeyType",
				Value:  jwa.RSA(),
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
				_, err := jwk.Import[jwk.Key](raw)
				require.Error(t, err, `jwk.Import should fail for empty key`)
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

		key, err := jwk.ParseKey[jwk.Key]([]byte(src))
		require.NoError(t, err, `jwk.ParseKey should succeed`)

		tp, err := key.Thumbprint(crypto.SHA256)
		require.NoError(t, err, "Thumbprint should succeed")
		require.Equal(t, expected, tp, "Thumbprint should match")
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
				_, err := jwk.Import[jwk.Key](raw)
				require.Error(t, err, `jwk.Import should fail for invalid key`)
			}
		})
		VerifyKey(t, map[string]keyDef{
			jwk.KeyTypeKey: {
				Method: "KeyType",
				Value:  jwa.EC(),
			},
			jwk.ECDSACrvKey: {
				Method: "Crv",
				Value:  jwa.P256(),
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
				_, err := jwk.Import[jwk.Key](raw)
				require.Error(t, err, `jwk.Import should fail for invalid key`)
			}
		})
		VerifyKey(t, map[string]keyDef{
			jwk.KeyTypeKey: {
				Method: "KeyType",
				Value:  jwa.EC(),
			},
			jwk.ECDSACrvKey: {
				Method: "Crv",
				Value:  jwa.P256(),
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
		algorithms := ourecdsa.Algorithms()
		require.True(t, len(algorithms) >= 3, `algorithm length should be greater than or equal to 3`)
		for _, alg := range algorithms {
			t.Run(alg.String(), func(t *testing.T) {
				key, err := jwxtest.GenerateEcdsaKey(alg)
				require.NoError(t, err, `jwxtest.GenerateEcdsaKey should succeed`)

				privkey, err := jwk.Import[jwk.Key](key)
				require.NoError(t, err, `jwk.Import should succeed`)

				pubkey, err := jwk.Import[jwk.Key](key)
				require.NoError(t, err, `jwk.Import should succeed`)

				privtp, err := privkey.Thumbprint(crypto.SHA512)
				require.NoError(t, err, `privkey.Thumbprint should succeed`)

				pubtp, err := pubkey.Thumbprint(crypto.SHA512)
				require.NoError(t, err, `pubkey.Thumbprint should succeed`)
				require.Equal(t, privtp, pubtp, `Thumbprints should match`)
			})
		}
	})
}

func TestSymmetric(t *testing.T) {
	t.Parallel()
	t.Run("Key", func(t *testing.T) {
		VerifyKey(t, map[string]keyDef{
			jwk.KeyTypeKey: {
				Method: "KeyType",
				Value:  jwa.OctetSeq(),
			},
			jwk.SymmetricOctetsKey: expectBase64(keyDef{
				Method: "Octets",
				Value:  "aGVsbG8K",
			}),
		})
	})
	t.Run("ImportCopiesCallerSlice", func(t *testing.T) {
		t.Parallel()
		buf := []byte("super-secret-hmac-key")
		want := append([]byte(nil), buf...)

		key, err := jwk.Import[jwk.SymmetricKey](buf)
		require.NoError(t, err)

		for i := range buf {
			buf[i] = 0
		}

		got, ok := key.Octets()
		require.True(t, ok)
		require.Equal(t, want, got, "JWK octets must not alias caller slice")
	})
}

func TestOKP(t *testing.T) {
	t.Parallel()

	ecdhkey, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err, `ecdh.P256().GenerateKey should succeed`)

	x, err := ecdhkey.ECDH(ecdhkey.PublicKey())
	require.NoError(t, err, `ecdhkey.ECDH should succeed`)

	log.Printf("ecdhkey.PublicKey().Bytes(): %x", ecdhkey.PublicKey().Bytes())

	_, ed25519privkey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err, `ed25519.GenerateKey should succeed`)

	keys := map[string][]struct {
		Name string
		Data map[string]keyDef
	}{
		"Ed25519": {
			{
				Name: "PrivateKey",
				Data: map[string]keyDef{
					jwk.KeyTypeKey: {
						Method: "KeyType",
						Value:  jwa.OKP(),
					},
					jwk.OKPDKey: expectBase64(keyDef{
						Method: "D",
						Value:  base64.EncodeToString(ed25519privkey.Seed()),
					}),
					jwk.OKPXKey: expectBase64(keyDef{
						Method: "X",
						Value:  base64.EncodeToString(ed25519privkey.Public().(ed25519.PublicKey)),
					}),
					jwk.OKPCrvKey: {
						Method: "Crv",
						Value:  jwa.Ed25519(),
					},
				},
			},
			{
				Name: "PublicKey",
				Data: map[string]keyDef{
					jwk.KeyTypeKey: {
						Method: "KeyType",
						Value:  jwa.OKP(),
					},
					jwk.OKPXKey: expectBase64(keyDef{
						Method: "X",
						Value:  base64.EncodeToString(ed25519privkey.Public().(ed25519.PublicKey)),
					}),
					jwk.OKPCrvKey: {
						Method: "Crv",
						Value:  jwa.Ed25519(),
					},
				},
			},
		},
		"ECDH": {
			{
				Name: "PrivateKey",
				Data: map[string]keyDef{
					jwk.KeyTypeKey: {
						Method: "KeyType",
						Value:  jwa.OKP(),
					},
					jwk.OKPDKey: expectBase64(keyDef{
						Method: "D",
						Value:  base64.EncodeToString(ecdhkey.Bytes()),
					}),
					jwk.OKPXKey: expectBase64(keyDef{
						Method: "X",
						Value:  base64.EncodeToString(x),
					}),
					jwk.OKPCrvKey: {
						Method: "Crv",
						Value:  jwa.X25519(),
					},
				},
			},
			{
				Name: "PublicKey",
				Data: map[string]keyDef{
					jwk.KeyTypeKey: {
						Method: "KeyType",
						Value:  jwa.OKP(),
					},
					jwk.OKPXKey: expectBase64(keyDef{
						Method: "X",
						Value:  base64.EncodeToString(x),
					}),
					jwk.OKPCrvKey: {
						Method: "Crv",
						Value:  jwa.X25519(),
					},
				},
			},
		},
	}

	for typ, keys := range keys {
		t.Run(typ, func(t *testing.T) {
			t.Parallel()
			for _, key := range keys {
				t.Run(key.Name, func(t *testing.T) {
					t.Parallel()
					VerifyKey(t, key.Data)
				})
			}
		})
	}
}

func TestCustomField(t *testing.T) {
	const rfc3339Key = `x-rfc3339-key`
	const rfc1123Key = `x-rfc1123-key`

	// XXX has global effect!!!
	jwk.RegisterCustomField[time.Time](rfc3339Key)
	jwk.RegisterCustomDecoder(rfc1123Key, jwk.CustomDecodeFunc[time.Time](func(data []byte) (time.Time, error) {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return time.Time{}, err
		}
		return time.Parse(time.RFC1123, s)
	}))
	defer jwk.UnregisterCustomField(rfc3339Key)
	defer jwk.UnregisterCustomField(rfc1123Key)

	expected := time.Date(2015, 11, 4, 5, 12, 52, 0, time.UTC)
	rfc3339bytes, _ := expected.MarshalText() // RFC3339
	rfc1123bytes := expected.Format(time.RFC1123)

	var b strings.Builder
	b.WriteString(`{"e":"AQAB", "kty":"RSA", "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","`)
	b.WriteString(rfc3339Key)
	b.WriteString(`":"`)
	b.Write(rfc3339bytes)
	b.WriteString(`","`)
	b.WriteString(rfc1123Key)
	b.WriteString(`":"`)
	b.WriteString(rfc1123bytes)
	b.WriteString(`"}`)
	src := b.String()

	t.Run("jwk.ParseKey", func(t *testing.T) {
		key, err := jwk.ParseKey[jwk.Key]([]byte(src))
		require.NoError(t, err, `jwk.ParseKey should succeed`)

		for _, name := range []string{rfc3339Key, rfc1123Key} {
			v, ok := key.Field(name)
			require.True(t, ok, `key.Field(%q) should succeed`, name)
			tv, ok := v.(time.Time)
			require.True(t, ok, `value should be time.Time`)
			require.Equal(t, expected, tv, `values should match`)
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
	key, err := jwk.ParseKey[jwk.Key]([]byte(src), jwk.WithPEM(true))
	require.NoError(t, err, `jwk.ParseKey should succeed`)
	require.Equal(t, jwa.RSA(), key.KeyType(), `key type should be RSA`)

	pubkey, err := jwk.Export[*rsa.PublicKey](key)
	require.NoError(t, err, `key.Raw should succeed`)

	N := &big.Int{}
	N, _ = N.SetString(`779390807991489150242580488277564408218067197694419403671246387831173881192316375931050469298375090533614189460270485948672580508192398132571230359681952349714254730569052029178325305344289615160181016909374016900403698428293142159695593998453788610098596363011884623801134548926432366560975619087466760747503535615491182090094278093592303467050094984372887804234341012289019841973178427045121609424191835554013017436743418746919496835541323790719629313070434897002108079086472354410640690933161025543816362962891190753195691593288890628966181309776957070655619665306995097798188588453327627252794498823229009195585001242181503742627414517186199717150645163224325403559815442522031412813762764879089624715721999552786759649849125487587658121901233329199571710176245013452847516179837767710027433169340850618643815395642568876192931279303797384539146396956216244189819533317558165234451499206045369678277987397913889177569796721689284116762473340601498426367267765652880247655009239893325078809797979771964770948333084772104541394544131668212262901583064272659565503500144472388676955404823979083054620299811247635425415371418720649368570747531327436083928369741631909855731133100553629456091216238379430154237251461586878393695925917`, 10)

	require.Equal(t, N, pubkey.N, `value for N should match`)
	require.Equal(t, 65537, pubkey.E, `value for E should amtch`)
}

// TestRSAExportIndependentN is a regression guard for JWK-INT-004:
// buildRSAPublicKey used to assign a pool-borrowed *big.Int to
// rsa.PublicKey.N. Any future "fix" that returned that pooled value via
// defer Put would zero the caller's N on return. Each export must own
// its own independent big.Int, and mutating one result must not affect
// another.
func TestRSAExportIndependentN(t *testing.T) {
	priv, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err, `jwxtest.GenerateRsaJwk should succeed`)
	key, err := priv.PublicKey()
	require.NoError(t, err, `PublicKey should succeed`)

	pub1, err := jwk.Export[*rsa.PublicKey](key)
	require.NoError(t, err, `first Export should succeed`)
	pub2, err := jwk.Export[*rsa.PublicKey](key)
	require.NoError(t, err, `second Export should succeed`)

	require.Equal(t, 0, pub1.N.Cmp(pub2.N), `both exports must decode to the same modulus`)
	require.NotSame(t, pub1.N, pub2.N, `each export must own an independent *big.Int`)

	original := new(big.Int).Set(pub1.N)
	pub2.N.SetInt64(0)
	require.Equal(t, 0, pub1.N.Cmp(original), `mutating pub2.N must not corrupt pub1.N`)
}

type typedField struct {
	Foo string
	Bar int64
}

func TestTypedFields(t *testing.T) {
	expected := &typedField{Foo: "Foo", Bar: 0xdeadbeef}
	var keys []jwk.Key
	{
		k1, e1 := jwxtest.GenerateRsaJwk()
		require.NoError(t, e1, `jwxtest.GenerateRsaJwk should succeed`)
		k2, e2 := jwxtest.GenerateEcdsaJwk()
		require.NoError(t, e2, `jwxtest.GenerateEcdsaJwk should succeed`)
		k3, e3 := jwxtest.GenerateSymmetricJwk()
		require.NoError(t, e3, `jwxtest.GenerateSymmetricJwk should succeed`)
		k4, e4 := jwxtest.GenerateEd25519Jwk()
		require.NoError(t, e4, `jwxtest.GenerateEd25519Jwk should succeed`)
		keys = []jwk.Key{k1, k2, k3, k4}
	}
	for _, key := range keys {
		key.Set("typed-field", expected)
	}

	testcases := []struct {
		Name        string
		Options     []jwk.ParseOption
		PostProcess func(*testing.T, any) (*typedField, error)
	}{
		{
			Name:    "Basic",
			Options: []jwk.ParseOption{jwk.WithTypedField("typed-field", typedField{})},
			PostProcess: func(t *testing.T, field any) (*typedField, error) {
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
			PostProcess: func(t *testing.T, field any) (*typedField, error) {
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
		serialized, err := json.Marshal(key)
		require.NoError(t, err, `json.Marshal should succeed`)
		t.Run(fmt.Sprintf("%T", key), func(t *testing.T) {
			for _, tc := range testcases {
				t.Run(tc.Name, func(t *testing.T) {
					got, err := jwk.ParseKey[jwk.Key](serialized, tc.Options...)
					require.NoError(t, err, `jwk.Parse should succeed`)
					v, ok := got.Field("typed-field")
					require.True(t, ok, `got.Field() should succeed`)

					field, err := tc.PostProcess(t, v)
					require.NoError(t, err, `tc.PostProcess should succeed`)
					require.Equal(t, field, expected, `field should match expected value`)
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
		require.NoError(t, err, `json.Marshal should succeed`)

		for _, tc := range testcases {
			t.Run(tc.Name, func(t *testing.T) {
				got, err := jwk.Parse(serialized, tc.Options...)
				require.NoError(t, err, `jwk.Parse should succeed`)

				for i := range got.Len() {
					key, ok := got.Key(i)
					require.True(t, ok, `got.Key() should succeed`)
					v, ok := key.Field("typed-field")
					require.True(t, ok, `key.Field() should succeed`)
					field, err := tc.PostProcess(t, v)
					require.NoError(t, err, `tc.PostProcess should succeed`)

					require.Equal(t, field, expected, `field should match expected value`)
				}
			})
		}
	})
}

func TestGH412(t *testing.T) {
	base := jwk.NewSet()

	const iterations = 5
	kids := make(map[string]struct{})
	for i := range iterations {
		k, err := jwxtest.GenerateRsaJwk()
		require.NoError(t, err, `jwxttest.GenerateRsaJwk() should succeed`)

		kid := "key-" + strconv.Itoa(i)
		k.Set(jwk.KeyIDKey, kid)
		base.AddKey(k)
		kids[kid] = struct{}{}
	}

	for i := range iterations {
		idx := i
		currentKid := "key-" + strconv.Itoa(i)
		t.Run(fmt.Sprintf("Remove at position %d", i), func(t *testing.T) {
			set, err := base.Clone()
			require.NoError(t, err, `base.Clone() should succeed`)
			require.Equal(t, iterations, set.Len(), `set.Len should be %d`, iterations)

			k, ok := set.Key(idx)
			require.True(t, ok, `set.Get should succeed`)
			require.NoError(t, set.RemoveKey(k), `set.Remove should succeed`)
			kid, ok := k.KeyID()
			require.True(t, ok, `k.KeyID should succeed`)
			t.Logf("deleted key %s", kid)

			require.Equal(t, iterations-1, set.Len(), `set.Len should be %d`, iterations-1)

			expected := make(map[string]struct{})
			for k := range kids {
				if k == currentKid {
					continue
				}
				expected[k] = struct{}{}
			}

			for i := range set.Len() {
				key, ok := set.Key(i)
				require.True(t, ok, `set.Key() should succeed`)
				gotkid, ok := key.KeyID()
				require.True(t, ok, `key.KeyID should succeed`)
				require.NotEqual(t, kid, gotkid, `key id should not match`)
				delete(expected, gotkid)
			}

			require.Len(t, expected, 0, `expected map should be empty`)
		})
	}
}

func TestGH491(t *testing.T) {
	msg := `{"keys":[{"alg":"ECMR","crv":"P-521","key_ops":["deriveKey"],"kty":"EC","x":"AEFldixpd6xWI1rPigk_i_fW_9SLXh3q3h_CbmRIJ2vmnneWnfylvg37q9_BeSxhLpTQkq580tP-7QiOoNem4ubg","y":"AD8MroFIWQI4nm1rVKOb0ImO0Y7EzPt1HTQfZxagv2IoMez8H_vV7Ra9fU7lJhoe3v-Th6x3-4540FodeIxxiphn"},{"alg":"ES512","crv":"P-521","key_ops":["verify"],"kty":"EC","x":"AFZApUzXzvjVJCZQX1De3LUudI7fiWZcZS3t4F2yrxn0tItCYIZrfygPiCZfV1hVKa3WuH2YMrISZUPrSgi_RN2d","y":"ASEyw-_9xcwNBnvpT7thmAF5qHv9-UPYf38AC7y5QBVejQH_DO1xpKzlTbrHCz0jrMeEir8TyW5ywZIYnqGzPBpn"}]}`
	keys, err := jwk.Parse([]byte(msg))
	require.NoError(t, err, `jwk.Parse should succeed`)

	// there should be 2 keys , get the first key
	k, _ := keys.Key(0)
	ops, ok := k.KeyOps()
	require.True(t, ok, `k.KeyOps should succeed`)
	require.Equal(t, jwk.KeyOperationList{jwk.KeyOpDeriveKey}, ops, `k.KeyOps should match`)
}

func TestSetWithPrivateParams(t *testing.T) {
	k1, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err, `jwxtest.GenerateRsaJwk should succeed`)

	k2, err := jwxtest.GenerateEcdsaJwk()
	require.NoError(t, err, `jwxtest.GenerateEcdsaJwk should succeed`)

	k3, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err, `jwxtest.GenerateSymmetricJwk should succeed`)

	t.Run("JWK instead of JWKS", func(t *testing.T) {
		var buf bytes.Buffer
		_ = k1.Set(`renewal_kid`, "foo")
		_ = json.MarshalEncode(json.NewEncoder(&buf), k1)

		var check = func(t *testing.T, buf []byte) {
			set, err := jwk.Parse(buf)
			require.NoError(t, err, `jwk.Parse should succeed`)
			require.Equal(t, 1, set.Len(), `set.Len() should be 1`)

			kidV, ok := set.Field(`renewal_kid`)
			require.True(t, ok, `set.Field("renewal_kid") should succeed`)
			kid, ok := kidV.(string)
			require.True(t, ok, `renewal_kid should be a string`)

			require.Equal(t, `foo`, kid, `set.Field("renewal_kid") should return "foo"`)

			key, ok := set.Key(0)
			require.True(t, ok, `set.Key(0) should return ok = true`)

			kidV2, ok := key.Field(`renewal_kid`)
			require.True(t, ok, `key.Field("renewal_kid") should succeed`)
			kid2, ok := kidV2.(string)
			require.True(t, ok, `renewal_kid should be a string`)

			require.Equal(t, `foo`, kid2, `key.Field("renewal_kid") should return "foo"`)
		}

		t.Run("Check original buffer", func(t *testing.T) {
			check(t, buf.Bytes())
		})
		t.Run("Check serialized", func(t *testing.T) {
			set, err := jwk.Parse(buf.Bytes())
			require.NoError(t, err, `jwk.Parse should succeed`)

			js, err := json.MarshalIndent(set, "", "  ")
			require.NoError(t, err, `json.MarshalIndent should succeed`)
			check(t, js)
		})
	})
	t.Run("JWKS with multiple keys", func(t *testing.T) {
		var buf bytes.Buffer
		buf.WriteString(`{"renewal_kid":"foo","keys":[`)
		b1, _ := json.Marshal(k1)
		buf.Write(b1)
		buf.WriteByte(tokens.Comma)
		b2, _ := json.Marshal(k2)
		buf.Write(b2)
		buf.WriteByte(tokens.Comma)
		b3, _ := json.Marshal(k3)
		buf.Write(b3)
		buf.WriteString(`]}`)

		var check = func(t *testing.T, buf []byte) {
			set, err := jwk.Parse(buf)
			require.NoError(t, err, `jwk.Parse should succeed`)
			require.Equal(t, 3, set.Len(), `set.Len() should be 3`)

			v, ok := set.Field(`renewal_kid`)
			require.True(t, ok, `set.Field("renewal_kid") should succeed`)

			require.Equal(t, `foo`, v, `set.Field("renewal_kid") should return "foo"`)
		}

		t.Run("Check original buffer", func(t *testing.T) {
			check(t, buf.Bytes())
		})
		t.Run("Check serialized", func(t *testing.T) {
			set, err := jwk.Parse(buf.Bytes())
			require.NoError(t, err, `jwk.Parse should succeed`)

			js, err := json.MarshalIndent(set, "", "  ")
			require.NoError(t, err, `json.MarshalIndent should succeed`)
			check(t, js)
		})
	})
	t.Run("Set private parameters", func(t *testing.T) {
		set := jwk.NewSet()
		require.NoError(t, set.Set(`renewal_kid`, `foo`), `set.Set should succeed`)

		v, ok := set.Field(`renewal_kid`)
		require.True(t, ok, `set.Field("renewal_kid") should succeed`)

		require.Equal(t, `foo`, v, `set.Field("renewal_kid") should return "foo"`)
		require.Error(t, set.Set(`keys`, []string{"foo"}), `set.Set should fail`)

		k, err := jwk.Import[jwk.Key]([]byte("foobar"))
		require.NoError(t, err, `jwk.Import should succeed`)

		keys := []jwk.Key{k}
		require.NoError(t, set.Set(`keys`, keys), `set.Set should succeed`)
		require.Equal(t, set.Len(), 1, `set should have 1 key`)
	})
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

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(`Content-Type`, `application/json`)
		w.WriteHeader(http.StatusOK)

		io.WriteString(w, src)
	}))
	defer srv.Close()

	// Cache-based ignoreParseError tests moved to ext/jwkfetch

	// Test the case when WithIgnoreParseError is passed to ParseKey
	t.Run(`ParseKey + WithIgnoreParseError should be an error`, func(t *testing.T) {
		key, err := jwxtest.GenerateRsaJwk()
		require.NoError(t, err, `jwxtest.GenerateRsaJwk() should succeed`)

		buf, err := json.Marshal(key)
		require.NoError(t, err, `json.Marshal should succeed`)

		_, err = jwk.ParseKey[jwk.Key](buf)
		require.NoError(t, err, `jwk.ParseKey (no WithIgnoreParseError) should succeed`)

		_, err = jwk.ParseKey[jwk.Key](buf, jwk.WithIgnoreParseError(true))
		require.Error(t, err, `jwk.ParseKey (no WithIgnoreParseError) should fail`)
	})
}

// This test existed to test if we can handle it when the user nukes
// the private keys' precomputed values. But as of go1.24 the values
// are validated by the crypto/rsa package, so we just let crypto/rsa
// Do The Right Thing, and not deal with it. This test is commented out
// for the time being; we should remove it once we no longer support
// any of the Go versions that _dont_ validate these values.
/*
func TestGH664(t *testing.T) {
	privkey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err, `jwxtext.GenerateRsaKey() should succeed`)

	// first, test a stupid case where Primes > 2
	privkey.Primes = append(privkey.Primes, &big.Int{})
	_, err = jwk.Import[jwk.Key](privkey)
	require.Error(t, err, `jwk.Import should fail`)

	privkey.Primes = privkey.Primes[:2]

	// nuke p and q, dp, dq, qi
	for i := range 3 {
		t.Run(fmt.Sprintf("Check what happens when primes are reduced to %d", i), func(t *testing.T) {
			privkey.Primes = privkey.Primes[:i]
			privkey.Precomputed.Dp = nil
			privkey.Precomputed.Dq = nil
			privkey.Precomputed.Qinv = nil
			privkey.Precomputed.CRTValues = nil

			jwkPrivkey, err := jwk.Import[jwk.Key](privkey)
			require.NoError(t, err, `jwk.Import should succeed`)

			buf, _ := json.MarshalIndent(jwkPrivkey, "", "  ")
			parsed, err := jwk.ParseKey[jwk.Key](buf)
			require.NoError(t, err, `jwk.ParseKey should succeed`)

			payload := []byte(`hello , world!`)
			signed, err := jws.Sign(payload, jws.WithKey(jwa.RS256(), parsed))
			require.NoError(t, err, `jws.Sign should succeed`)

			verified, err := jws.Verify(signed, jws.WithKey(jwa.RS256(), privkey.PublicKey))
			require.NoError(t, err, `jws.Verify should succeed`)
			require.Equal(t, payload, verified, `verified content should match`)
		})
	}
}
*/

func TestGH730(t *testing.T) {
	key, err := jwk.Import[jwk.Key]([]byte(`abracadabra`))
	require.NoError(t, err, `jwk.Import should succeed`)
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(key), `first AddKey should succeed`)
	require.Error(t, set.AddKey(key), `second AddKey should fail`)
}

// This test was lifted from #875. See tests under Roundtrip/WithPEM(true) for other key types
func TestECDSAPEM(t *testing.T) {
	// go make an EC key at https://mkjwk.org/
	key, err := jwk.ParseKey[jwk.Key]([]byte(`{
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
	_, err = jwk.ParseKey[jwk.Key](pem, jwk.WithPEM(true))
	if err != nil {
		t.Fatal(err)
	}
}

func TestGH947(t *testing.T) {
	// AS OP described it. Below case will panic if the problem exists,
	raw := []byte(`{"crv":"Ed25519","d":"","x":"","kty":"OKP"}`)
	k, err := jwk.ParseKey[jwk.Key](raw)
	require.NoError(t, err, `jwk.ParseKey should succeed`)
	_, err = jwk.Export[any](k)
	require.Error(t, err, `(okpkey).Raw with 0-length OKP key should fail`)
}

func TestValidation(t *testing.T) {
	{
		key, err := jwxtest.GenerateRsaJwk()
		require.NoError(t, err, `jwx.GenerateRsaJwk should succeed`)
		require.NoError(t, key.Validate(), `key.Validate should succeed (vanilla key)`)

		require.NoError(t, key.Set(jwk.RSADKey, []byte(nil)), `key.Set should succeed`)
		require.Error(t, key.Validate(), `key.Validate should fail`)
	}

	{
		key, err := jwxtest.GenerateEcdsaJwk()
		require.NoError(t, err, `jwx.GenerateEcdsaJwk should succeed`)
		require.NoError(t, key.Validate(), `key.Validate should succeed`)

		x, ok := key.(jwk.ECDSAPrivateKey).X()
		require.True(t, ok, `key.(jwk.ECDSAPrivateKey).X should succeed`)
		require.NoError(t, key.Set(jwk.ECDSAXKey, x[:len(x)/2]), `key.Set should succeed`)
		require.Error(t, key.Validate(), `key.Validate should fail`)

		require.NoError(t, key.Set(jwk.ECDSAXKey, x), `key.Set should succeed`)
		require.NoError(t, key.Validate(), `key.Validate should succeed`)

		require.NoError(t, key.Set(jwk.ECDSADKey, []byte(nil)), `key.Set should succeed`)
		require.Error(t, key.Validate(), `key.Validate should fail`)
	}

	{
		key, err := jwxtest.GenerateEd25519Jwk()
		require.NoError(t, err, `jwx.GenerateEd25519Jwk should succeed`)
		require.NoError(t, key.Validate(), `key.Validate should succeed`)
		x, ok := key.(jwk.OKPPrivateKey).X()
		require.True(t, ok, `key.(jwk.OKPPrivateKey).X should succeed`)
		require.NoError(t, key.Set(jwk.OKPXKey, []byte(nil)), `key.Set should succeed`)
		require.Error(t, key.Validate(), `key.Validate should fail`)

		require.NoError(t, key.Set(jwk.OKPXKey, x), `key.Set should succeed`)
		require.NoError(t, key.Validate(), `key.Validate should succeed`)

		require.NoError(t, key.Set(jwk.OKPDKey, []byte(nil)), `key.Set should succeed`)
		require.Error(t, key.Validate(), `key.Validate should fail`)
	}

	{
		key, err := jwxtest.GenerateSymmetricJwk()
		require.NoError(t, err, `jwx.GenerateSymmetricJwk should succeed`)
		require.NoError(t, key.Validate(), `key.Validate should succeed`)

		require.NoError(t, key.Set(jwk.SymmetricOctetsKey, []byte(nil)), `key.Set should succeed`)
		require.Error(t, key.Validate(), `key.Validate should fail`)
	}
}

func TestParse_fail(t *testing.T) {
	t.Parallel()
	t.Run(`malformed json`, func(t *testing.T) {
		t.Parallel()
		const src = `{blah}`
		t.Run("string", func(t *testing.T) {
			t.Parallel()
			_, err := jwk.ParseString(src)
			require.Error(t, err, `jwk.ParseString should fail`)
			require.ErrorIs(t, err, jwk.ParseError(), `error should be ParseError`)
			require.True(t, strings.HasPrefix(err.Error(), `jwk.ParseString: `))
		})
		t.Run("[]byte", func(t *testing.T) {
			t.Parallel()
			_, err := jwk.Parse([]byte(src))
			require.Error(t, err, `jwk.Parse should fail`)
			require.ErrorIs(t, err, jwk.ParseError(), `error should be ParseError`)
			require.True(t, strings.HasPrefix(err.Error(), `jwk.Parse: `))
		})
		t.Run("io.Reader", func(t *testing.T) {
			t.Parallel()
			_, err := jwk.ParseReader(strings.NewReader(src))
			require.Error(t, err, `jwk.ParseReader should fail`)
			require.ErrorIs(t, err, jwk.ParseError(), `error should be ParseError`)
			require.True(t, strings.HasPrefix(err.Error(), `jwk.ParseReader: `))
		})
	})
}

func TestGH1262(t *testing.T) {
	t.Run("Updated Example test", func(t *testing.T) {
		keyCli, err := ecdh.P384().GenerateKey(rand.Reader)
		require.NoError(t, err, `ecdh.P384().GenerateKey should succeed`)

		jwkCliPriv, err := jwk.Import[jwk.Key](keyCli)
		require.NoError(t, err, `jwk.Import should succeed`)
		_ = jwkCliPriv

		rawCliPriv, err := jwk.Export[*ecdh.PrivateKey](jwkCliPriv)
		require.NoError(t, err, `jwk.Export should succeed`)
		_ = rawCliPriv

		pubCli := keyCli.PublicKey() // server is able to retrieve the pub key part of client

		keySrv, err := ecdh.P384().GenerateKey(rand.Reader)
		require.NoError(t, err, `ecdh.P384().GenerateKey should succeed`)

		jwkSrv, err := jwk.Import[jwk.Key](keySrv.PublicKey())
		require.NoError(t, err, `jwk.Import should succeed`)
		jwkBuf, err := json.Marshal(jwkSrv)

		require.NoError(t, err, `json.Marshal should succeed`)

		secretSrv, err := keySrv.ECDH(pubCli)
		require.NoError(t, err, `keySrv.ECDH should succeed`)

		_ = secretSrv // doing some non-standard encryption & response with encrypted data

		// client
		jwkCli, err := jwk.ParseKey[jwk.Key](jwkBuf) // extract jwkBuf
		require.NoError(t, err, `jwk.ParseKey should succeed`)

		pubSrv, err := jwk.Export[*ecdh.PublicKey](jwkCli)
		require.NoError(t, err, `jwk.Export should succeed`)
		secretCli, err := keyCli.ECDH(pubSrv)
		require.NoError(t, err, `keyCli.ECDH should succeed`)

		_ = secretCli // doing some non-standard encryption
	})
}

// DirectEmbed embeds jwk.Key directly
type DirectEmbed struct {
	jwk.Key
}

// IndirectEmbed embeds DirectEmbed which embeds jwk.Key
type IndirectEmbed struct {
	DirectEmbed
}

// DoubleIndirectEmbed embeds IndirectEmbed which embeds DirectEmbed which embeds jwk.Key
type DoubleIndirectEmbed struct {
	IndirectEmbed
}

func TestExportEmbeddedKey(t *testing.T) {
	t.Run("Direct Embed", func(t *testing.T) {
		// Create a RSA key
		rsaKey, err := jwxtest.GenerateRsaJwk()
		require.NoError(t, err, "jwxtest.GenerateRsaJwk should succeed")

		// Create a direct embedding
		directEmbed := &DirectEmbed{Key: rsaKey}

		// Export the key from the direct embedding
		rawKeyV, err := jwk.Export[*rsa.PrivateKey](directEmbed)
		require.NoError(t, err, "jwk.Export should succeed with direct embed")
		_ = rawKeyV
	})

	t.Run("Indirect Embed", func(t *testing.T) {
		// Create a RSA key
		rsaKey, err := jwxtest.GenerateRsaJwk()
		require.NoError(t, err, "jwxtest.GenerateRsaJwk should succeed")

		// Create an indirect embedding
		directEmbed := DirectEmbed{Key: rsaKey}
		indirectEmbed := &IndirectEmbed{DirectEmbed: directEmbed}

		// Export the key from the indirect embedding
		rawKeyV, err := jwk.Export[*rsa.PrivateKey](indirectEmbed)
		if err != nil {
			t.Logf("Error: %s", err)
		}
		require.NoError(t, err, "jwk.Export should succeed with indirect embed")
		_ = rawKeyV
	})

	t.Run("Double Indirect Embed", func(t *testing.T) {
		// Create a RSA key
		rsaKey, err := jwxtest.GenerateRsaJwk()
		require.NoError(t, err, "jwxtest.GenerateRsaJwk should succeed")

		// Create a double indirect embedding
		directEmbed := DirectEmbed{Key: rsaKey}
		indirectEmbed := IndirectEmbed{DirectEmbed: directEmbed}
		doubleIndirectEmbed := &DoubleIndirectEmbed{IndirectEmbed: indirectEmbed}

		// Export the key from the double indirect embedding
		rawKeyV, err := jwk.Export[*rsa.PrivateKey](doubleIndirectEmbed)
		require.NoError(t, err, "jwk.Export should succeed with double indirect embed")
		_ = rawKeyV
	})
}

func TestPEMDecodeFunc(t *testing.T) {
	// PEMDecodeFunc should adapt a plain function to PEMDecoder and
	// forward the call verbatim.
	wantRaw := []byte("raw")
	wantRest := []byte("rest")
	wantErr := errors.New("boom")
	var got []byte
	var dec jwk.PEMDecoder = jwk.PEMDecodeFunc(func(src []byte) (any, []byte, error) {
		got = src
		return wantRaw, wantRest, wantErr
	})

	raw, rest, err := dec.Decode([]byte("src"))
	require.Equal(t, []byte("src"), got, "adapter should forward the input")
	require.Equal(t, any(wantRaw), raw)
	require.Equal(t, wantRest, rest)
	require.ErrorIs(t, err, wantErr)
}

func TestOKPRawKeyImporterFunc(t *testing.T) {
	// OKPRawKeyImporterFunc should adapt a plain function to the
	// OKPRawKeyImporter interface and forward the call verbatim.
	wantX := []byte{0x01}
	wantD := []byte{0x02}
	var got any
	var imp jwk.OKPRawKeyImporter = jwk.OKPRawKeyImporterFunc(func(key any) (jwa.EllipticCurveAlgorithm, []byte, []byte, bool) {
		got = key
		return jwa.Ed25519(), wantX, wantD, true
	})

	crv, x, d, ok := imp.ImportOKPRawKey("sentinel")
	require.True(t, ok)
	require.Equal(t, "sentinel", got)
	require.Equal(t, jwa.Ed25519(), crv)
	require.Equal(t, wantX, x)
	require.Equal(t, wantD, d)
}

func TestWithPEMDecoder(t *testing.T) {
	// Generate a valid RSA private key
	privateKey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)

	// Encode it to PEM format
	pemData, err := jwk.EncodePEM(privateKey)
	require.NoError(t, err)

	// Create a PEM decoder
	decoder := jwk.NewPEMDecoder()

	// Test that Parse with WithPEMDecoder works correctly
	parsedKey, err := jwk.Parse(pemData, jwk.WithPEM(true), jwk.WithPEMDecoder(decoder))
	require.NoError(t, err, "Parse should succeed with valid PEM data and custom decoder")
	require.NotNil(t, parsedKey, "Parsed key should not be nil")
}

func TestRegisterX509Decoder(t *testing.T) {
	// Generate a real RSA key for testing
	testKey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)

	// Create a custom decoder that handles a custom PEM type and returns the test key
	customIdent := "test-custom-decoder"
	customDecoder := jwk.X509DecodeFunc(func(block *pem.Block) (any, error) {
		if block.Type == "TEST CUSTOM KEY" {
			return testKey, nil
		}
		return nil, fmt.Errorf("unsupported type or block")
	})

	// Register the custom decoder
	jwk.RegisterX509Decoder(customIdent, customDecoder)

	// Create test PEM data with our custom type
	testPEMData := `-----BEGIN TEST CUSTOM KEY-----
dGVzdCBkYXRh
-----END TEST CUSTOM KEY-----`

	// Test that our custom decoder can handle this via ParseKey
	parsedKey, err := jwk.ParseKey[jwk.Key]([]byte(testPEMData), jwk.WithPEM(true))
	require.NoError(t, err)
	require.NotNil(t, parsedKey)

	// Verify we get back a valid RSA key
	require.Equal(t, "RSA", parsedKey.KeyType().String())

	// Clean up: unregister the decoder
	jwk.UnregisterX509Decoder(customIdent)
}

func TestUnregisterX509Decoder(t *testing.T) {
	// Generate a real RSA key for testing
	testKey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)

	// Create a custom decoder
	customIdent := "test-unregister-decoder"
	customDecoder := jwk.X509DecodeFunc(func(block *pem.Block) (any, error) {
		if block.Type == "TEST UNREGISTER" {
			return testKey, nil
		}
		return nil, fmt.Errorf("unsupported type or block")
	})

	// Register the decoder
	jwk.RegisterX509Decoder(customIdent, customDecoder)

	// Create test PEM data
	testPEMData := `-----BEGIN TEST UNREGISTER-----
dGVzdCBkYXRh
-----END TEST UNREGISTER-----`

	// Verify it works when registered
	parsedKey1, err := jwk.ParseKey[jwk.Key]([]byte(testPEMData), jwk.WithPEM(true))
	require.NoError(t, err)
	require.NotNil(t, parsedKey1)

	// Now unregister the decoder
	jwk.UnregisterX509Decoder(customIdent)

	// Verify it no longer works
	parsedKey2, err := jwk.ParseKey[jwk.Key]([]byte(testPEMData), jwk.WithPEM(true))
	require.Error(t, err)
	require.Nil(t, parsedKey2)
}

func TestRegisterX509Decoder_NilPanic(t *testing.T) {
	// Test that registering nil decoder panics
	require.Panics(t, func() {
		jwk.RegisterX509Decoder("test", nil)
	})
}

func TestRegisterX509Decoder_DuplicateRegistration(t *testing.T) {
	// Generate a test key for verification
	testKey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)

	// Create a custom decoder that handles a specific PEM type
	customIdent := "test-duplicate-decoder"
	callCount := 0
	decoder := jwk.X509DecodeFunc(func(block *pem.Block) (any, error) {
		callCount++
		if block.Type == "TEST DUPLICATE" {
			return testKey, nil
		}
		return nil, fmt.Errorf("unsupported type")
	})

	// Register the decoder
	jwk.RegisterX509Decoder(customIdent, decoder)

	// Create test PEM data
	testPEMData := `-----BEGIN TEST DUPLICATE-----
dGVzdCBkYXRh
-----END TEST DUPLICATE-----`

	// Verify it works after first registration
	parsedKey1, err := jwk.ParseKey[jwk.Key]([]byte(testPEMData), jwk.WithPEM(true))
	require.NoError(t, err)
	require.NotNil(t, parsedKey1)
	require.Equal(t, 1, callCount, "Decoder should be called once")

	// Register it again (duplicate) - should be idempotent
	jwk.RegisterX509Decoder(customIdent, decoder)

	// Verify it still works after duplicate registration and decoder wasn't added twice
	parsedKey2, err := jwk.ParseKey[jwk.Key]([]byte(testPEMData), jwk.WithPEM(true))
	require.NoError(t, err)
	require.NotNil(t, parsedKey2)
	require.Equal(t, 2, callCount, "Decoder should be called once more, not duplicated")

	// Clean up
	jwk.UnregisterX509Decoder(customIdent)
}

func TestUnregisterX509Decoder_NotRegistered(t *testing.T) {
	// Unregistering a non-existent decoder should be safe (no-op)
	require.NotPanics(t, func() {
		jwk.UnregisterX509Decoder("non-existent-decoder")
	})
}

// registerTrioDecoders registers three decoders that each recognize a
// distinct PEM block type. Callers receive the idents and a function
// that builds a PEM body for one of the types. Cleanup is registered
// via t.Cleanup so leftover decoders never leak across tests.
func registerTrioDecoders(t *testing.T) (identA, identB, identC string, pemFor func(string) []byte) {
	t.Helper()
	testKey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)

	mk := func(wantType string) jwk.X509Decoder {
		return jwk.X509DecodeFunc(func(block *pem.Block) (any, error) {
			if block.Type == wantType {
				return testKey, nil
			}
			return nil, fmt.Errorf("unsupported type")
		})
	}

	identA = "test-trio-A"
	identB = "test-trio-B"
	identC = "test-trio-C"
	require.NoError(t, jwk.RegisterX509Decoder(identA, mk("TRIO A")))
	require.NoError(t, jwk.RegisterX509Decoder(identB, mk("TRIO B")))
	require.NoError(t, jwk.RegisterX509Decoder(identC, mk("TRIO C")))

	t.Cleanup(func() {
		jwk.UnregisterX509Decoder(identA)
		jwk.UnregisterX509Decoder(identB)
		jwk.UnregisterX509Decoder(identC)
	})

	pemFor = func(typ string) []byte {
		return []byte("-----BEGIN " + typ + "-----\ndGVzdCBkYXRh\n-----END " + typ + "-----")
	}
	return identA, identB, identC, pemFor
}

// TestUnregisterX509Decoder_StaleIndexMiddle exercises JWK-003: after
// removing a decoder from the middle of the list, a subsequent
// unregister of a later-registered ident must not panic and must
// remove the correct decoder.
func TestUnregisterX509Decoder_StaleIndexMiddle(t *testing.T) {
	identA, identB, identC, pemFor := registerTrioDecoders(t)

	// Remove the middle decoder. Prior to the fix, the surviving
	// entry for identC kept its original index, which pointed past
	// the end of the shrunken slice.
	jwk.UnregisterX509Decoder(identB)

	// B must no longer decode.
	_, err := jwk.ParseKey[jwk.Key](pemFor("TRIO B"), jwk.WithPEM(true))
	require.Error(t, err, "TRIO B should fail after unregister")

	// A and C must still decode.
	_, err = jwk.ParseKey[jwk.Key](pemFor("TRIO A"), jwk.WithPEM(true))
	require.NoError(t, err, "TRIO A should still decode")
	_, err = jwk.ParseKey[jwk.Key](pemFor("TRIO C"), jwk.WithPEM(true))
	require.NoError(t, err, "TRIO C should still decode")

	// Now unregister C by ident. Before the fix this would panic
	// with an out-of-range slice index.
	require.NotPanics(t, func() {
		jwk.UnregisterX509Decoder(identC)
	})

	// C must no longer decode; A must still decode.
	_, err = jwk.ParseKey[jwk.Key](pemFor("TRIO C"), jwk.WithPEM(true))
	require.Error(t, err, "TRIO C should fail after second unregister")
	_, err = jwk.ParseKey[jwk.Key](pemFor("TRIO A"), jwk.WithPEM(true))
	require.NoError(t, err, "TRIO A must survive unrelated unregister")

	// Keep identA alive until cleanup fires.
	_ = identA
}

// TestUnregisterX509Decoder_StaleIndexFirst exercises the case where
// the removed element is at index 0 of the user-registered portion of
// the list. A later unregister for a surviving ident must still hit
// the correct decoder.
func TestUnregisterX509Decoder_StaleIndexFirst(t *testing.T) {
	identA, identB, identC, pemFor := registerTrioDecoders(t)

	jwk.UnregisterX509Decoder(identA)

	_, err := jwk.ParseKey[jwk.Key](pemFor("TRIO A"), jwk.WithPEM(true))
	require.Error(t, err)
	_, err = jwk.ParseKey[jwk.Key](pemFor("TRIO B"), jwk.WithPEM(true))
	require.NoError(t, err)
	_, err = jwk.ParseKey[jwk.Key](pemFor("TRIO C"), jwk.WithPEM(true))
	require.NoError(t, err)

	require.NotPanics(t, func() {
		jwk.UnregisterX509Decoder(identC)
	})

	_, err = jwk.ParseKey[jwk.Key](pemFor("TRIO C"), jwk.WithPEM(true))
	require.Error(t, err)
	_, err = jwk.ParseKey[jwk.Key](pemFor("TRIO B"), jwk.WithPEM(true))
	require.NoError(t, err, "TRIO B must survive unrelated unregister")

	_ = identB
}

// TestX509DecoderConcurrent runs parsers and register/unregister
// concurrently. Under -race this catches the in-place slice mutation
// that was racing with snapshot-then-iterate readers in decodeX509.
func TestX509DecoderConcurrent(t *testing.T) {
	testKey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)

	pemData := []byte("-----BEGIN TRIO CONCURRENT-----\ndGVzdCBkYXRh\n-----END TRIO CONCURRENT-----")
	decoder := jwk.X509DecodeFunc(func(block *pem.Block) (any, error) {
		if block.Type == "TRIO CONCURRENT" {
			return testKey, nil
		}
		return nil, fmt.Errorf("unsupported type")
	})

	stop := make(chan struct{})
	var wg sync.WaitGroup

	for range 8 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				// Best-effort parse; error is fine (decoder may be
				// unregistered at this moment). The point is that
				// the read path must not race on the decoder slice.
				_, _ = jwk.ParseKey[jwk.Key](pemData, jwk.WithPEM(true))
			}
		})
	}

	for i := range 200 {
		ident := fmt.Sprintf("test-concurrent-%d", i)
		require.NoError(t, jwk.RegisterX509Decoder(ident, decoder))
		jwk.UnregisterX509Decoder(ident)
	}

	close(stop)
	wg.Wait()
}

func TestGH1529(t *testing.T) {
	t.Run("Clone set with custom fields and modify", func(t *testing.T) {
		set1 := jwk.NewSet()
		require.NoError(t, set1.Set("foo", "bar"), `set1.Set should succeed`)

		set2, err := set1.Clone()
		require.NoError(t, err, `set1.Clone should succeed`)

		// Verify the custom field was copied during clone
		v2Initial, ok := set2.Field("foo")
		require.True(t, ok, `set2.Field should succeed after clone`)
		require.Equal(t, "bar", v2Initial, `set2 should have copied "foo" from set1`)

		// This should not error - cloned set should allow modifying the same field
		require.NoError(t, set2.Set("foo", "baz"), `set2.Set should succeed`)

		// Verify the sets are independent (modifying set2 doesn't affect set1)
		v1, ok := set1.Field("foo")
		require.True(t, ok, `set1.Field should succeed`)
		v2, ok := set2.Field("foo")
		require.True(t, ok, `set2.Field should succeed`)
		require.Equal(t, "bar", v1, `set1.Field("foo") should still return "bar"`)
		require.Equal(t, "baz", v2, `set2.Field("foo") should return "baz"`)
	})
}
