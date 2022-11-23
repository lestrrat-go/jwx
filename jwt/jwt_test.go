package jwt_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/internal/ecutil"
	"github.com/lestrrat-go/jwx/v2/internal/json"
	"github.com/lestrrat-go/jwx/v2/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwt/internal/types"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

/* This is commented out, because it is intended to cause compilation errors */
/*
func TestOption(t *testing.T) {
	var p jwt.ParseOption
	var v jwt.ValidateOption
	var o jwt.Option
	p = o // should be error
	v = o // should be error
	_ = p
	_ = v
}
*/

func TestJWTParse(t *testing.T) {
	t.Parallel()

	alg := jwa.RS256

	key, err := jwxtest.GenerateRsaKey()
	if !assert.NoError(t, err, `jwxtest.GenerateRsaKey should succeed`) {
		return
	}
	t1 := jwt.New()
	signed, err := jwt.Sign(t1, jwt.WithKey(alg, key))
	if !assert.NoError(t, err, `jwt.Sign should succeed`) {
		return
	}

	t.Logf("%s", signed)

	t.Run("Parse (no signature verification)", func(t *testing.T) {
		t.Parallel()
		t2, err := jwt.ParseInsecure(signed)
		if !assert.NoError(t, err, `jwt.Parse should succeed`) {
			return
		}
		if !assert.True(t, jwt.Equal(t1, t2), `t1 == t2`) {
			return
		}
	})
	t.Run("ParseString (no signature verification)", func(t *testing.T) {
		t.Parallel()
		t2, err := jwt.ParseString(string(signed), jwt.WithVerify(false), jwt.WithValidate(false))
		if !assert.NoError(t, err, `jwt.ParseString should succeed`) {
			return
		}
		if !assert.True(t, jwt.Equal(t1, t2), `t1 == t2`) {
			return
		}
	})
	t.Run("ParseReader (no signature verification)", func(t *testing.T) {
		t.Parallel()
		t2, err := jwt.ParseReader(bytes.NewReader(signed), jwt.WithVerify(false), jwt.WithValidate(false))
		if !assert.NoError(t, err, `jwt.ParseReader should succeed`) {
			return
		}
		if !assert.True(t, jwt.Equal(t1, t2), `t1 == t2`) {
			return
		}
	})
	t.Run("Parse (correct signature key)", func(t *testing.T) {
		t.Parallel()
		t2, err := jwt.Parse(signed, jwt.WithKey(alg, &key.PublicKey))
		if !assert.NoError(t, err, `jwt.Parse should succeed`) {
			return
		}
		if !assert.True(t, jwt.Equal(t1, t2), `t1 == t2`) {
			return
		}
	})
	t.Run("parse (wrong signature algorithm)", func(t *testing.T) {
		t.Parallel()
		_, err := jwt.Parse(signed, jwt.WithKey(jwa.RS512, &key.PublicKey))
		if !assert.Error(t, err, `jwt.Parse should fail`) {
			return
		}
	})
	t.Run("parse (wrong signature key)", func(t *testing.T) {
		t.Parallel()
		pubkey := key.PublicKey
		pubkey.E = 0 // bogus value
		_, err := jwt.Parse(signed, jwt.WithKey(alg, &pubkey))
		if !assert.Error(t, err, `jwt.Parse should fail`) {
			return
		}
	})
}

func TestJWTParseVerify(t *testing.T) {
	t.Parallel()

	keys := make([]interface{}, 0, 6)

	keys = append(keys, []byte("abracadabra"))

	rsaPrivKey, err := jwxtest.GenerateRsaKey()
	if !assert.NoError(t, err, "RSA key generated") {
		return
	}
	keys = append(keys, rsaPrivKey)

	for _, alg := range []jwa.EllipticCurveAlgorithm{jwa.P256, jwa.P384, jwa.P521} {
		ecdsaPrivKey, err := jwxtest.GenerateEcdsaKey(alg)
		if !assert.NoError(t, err, "jwxtest.GenerateEcdsaKey should succeed for %s", alg) {
			return
		}
		keys = append(keys, ecdsaPrivKey)
	}

	ed25519PrivKey, err := jwxtest.GenerateEd25519Key()
	if !assert.NoError(t, err, `jwxtest.GenerateEd25519Key should succeed`) {
		return
	}
	keys = append(keys, ed25519PrivKey)

	for _, key := range keys {
		key := key
		t.Run(fmt.Sprintf("Key=%T", key), func(t *testing.T) {
			t.Parallel()
			algs, err := jws.AlgorithmsForKey(key)
			if !assert.NoError(t, err, `jwas.AlgorithmsForKey should succeed`) {
				return
			}

			var dummyRawKey interface{}
			switch pk := key.(type) {
			case *rsa.PrivateKey:
				dummyRawKey, err = jwxtest.GenerateRsaKey()
				if !assert.NoError(t, err, `jwxtest.GenerateRsaKey should succeed`) {
					return
				}
			case *ecdsa.PrivateKey:
				curveAlg, ok := ecutil.AlgorithmForCurve(pk.Curve)
				if !assert.True(t, ok, `ecutil.AlgorithmForCurve should succeed`) {
					return
				}
				dummyRawKey, err = jwxtest.GenerateEcdsaKey(curveAlg)
				if !assert.NoError(t, err, `jwxtest.GenerateEcdsaKey should succeed`) {
					return
				}
			case ed25519.PrivateKey:
				dummyRawKey, err = jwxtest.GenerateEd25519Key()
				if !assert.NoError(t, err, `jwxtest.GenerateEd25519Key should succeed`) {
					return
				}
			case []byte:
				dummyRawKey = jwxtest.GenerateSymmetricKey()
			default:
				assert.Fail(t, fmt.Sprintf("Unhandled key type %T", key))
				return
			}

			testcases := []struct {
				SetAlgorithm   bool
				SetKid         bool
				InferAlgorithm bool
				Error          bool
			}{
				{
					SetAlgorithm:   true,
					SetKid:         true,
					InferAlgorithm: true,
				},
				{
					SetAlgorithm:   true,
					SetKid:         true,
					InferAlgorithm: false,
				},
				{
					SetAlgorithm:   true,
					SetKid:         false,
					InferAlgorithm: true,
					Error:          true,
				},
				{
					SetAlgorithm:   false,
					SetKid:         true,
					InferAlgorithm: true,
				},
				{
					SetAlgorithm:   false,
					SetKid:         true,
					InferAlgorithm: false,
					Error:          true,
				},
				{
					SetAlgorithm:   false,
					SetKid:         false,
					InferAlgorithm: true,
					Error:          true,
				},
				{
					SetAlgorithm:   true,
					SetKid:         false,
					InferAlgorithm: false,
					Error:          true,
				},
				{
					SetAlgorithm:   false,
					SetKid:         false,
					InferAlgorithm: false,
					Error:          true,
				},
			}
			for _, alg := range algs {
				alg := alg
				for _, tc := range testcases {
					tc := tc
					t.Run(fmt.Sprintf("Algorithm=%s, SetAlgorithm=%t, SetKid=%t, InferAlgorithm=%t, Expect Error=%t", alg, tc.SetAlgorithm, tc.SetKid, tc.InferAlgorithm, tc.Error), func(t *testing.T) {
						t.Parallel()

						const kid = "test-jwt-parse-verify-kid"
						const dummyKid = "test-jwt-parse-verify-dummy-kid"
						hdrs := jws.NewHeaders()
						hdrs.Set(jws.KeyIDKey, kid)

						t1 := jwt.New()
						signed, err := jwt.Sign(t1, jwt.WithKey(alg, key, jws.WithProtectedHeaders(hdrs)))
						if !assert.NoError(t, err, "token.Sign should succeed") {
							return
						}

						pubkey, err := jwk.PublicKeyOf(key)
						if !assert.NoError(t, err, `jwk.PublicKeyOf should succeed`) {
							return
						}

						if tc.SetAlgorithm {
							pubkey.Set(jwk.AlgorithmKey, alg)
						}

						dummyKey, err := jwk.PublicKeyOf(dummyRawKey)
						if !assert.NoError(t, err, `jwk.PublicKeyOf should succeed`) {
							return
						}

						if tc.SetKid {
							pubkey.Set(jwk.KeyIDKey, kid)
							dummyKey.Set(jwk.KeyIDKey, dummyKid)
						}

						// Permute on the location of the correct key, to check for possible
						// cases where we loop too little or too much.
						for i := 0; i < 6; i++ {
							var name string
							set := jwk.NewSet()
							switch i {
							case 0:
								name = "Lone key"
								set.AddKey(pubkey)
							case 1:
								name = "Two keys, correct one at the end"
								set.AddKey(dummyKey)
								set.AddKey(pubkey)
							case 2:
								name = "Two keys, correct one at the beginning"
								set.AddKey(pubkey)
								set.AddKey(dummyKey)
							case 3:
								name = "Three keys, correct one at the end"
								set.AddKey(dummyKey)
								set.AddKey(dummyKey)
								set.AddKey(pubkey)
							case 4:
								name = "Three keys, correct one at the middle"
								set.AddKey(dummyKey)
								set.AddKey(pubkey)
								set.AddKey(dummyKey)
							case 5:
								name = "Three keys, correct one at the beginning"
								set.AddKey(pubkey)
								set.AddKey(dummyKey)
								set.AddKey(dummyKey)
							}

							t.Run(name, func(t *testing.T) {
								options := []jwt.ParseOption{
									jwt.WithKeySet(set, jws.WithInferAlgorithmFromKey(tc.InferAlgorithm)),
								}
								t2, err := jwt.Parse(signed, options...)

								if tc.Error {
									assert.Error(t, err, `jwt.Parse should fail`)
									return
								}

								if !assert.NoError(t, err, `jwt.Parse should succeed`) {
									return
								}

								if !assert.True(t, jwt.Equal(t1, t2), `t1 == t2`) {
									return
								}
							})
						}
					})
				}
			}
		})
	}
	t.Run("Miscellaneous", func(t *testing.T) {
		key, err := jwxtest.GenerateRsaKey()
		if !assert.NoError(t, err, "RSA key generated") {
			return
		}
		const alg = jwa.RS256
		const kid = "my-very-special-key"
		hdrs := jws.NewHeaders()
		hdrs.Set(jws.KeyIDKey, kid)
		t1 := jwt.New()
		signed, err := jwt.Sign(t1, jwt.WithKey(alg, key, jws.WithProtectedHeaders(hdrs)))
		if !assert.NoError(t, err, "token.Sign should succeed") {
			return
		}

		t.Run("Alg does not match", func(t *testing.T) {
			t.Parallel()
			pubkey, err := jwk.PublicKeyOf(key)
			if !assert.NoError(t, err) {
				return
			}

			pubkey.Set(jwk.AlgorithmKey, jwa.HS256)
			pubkey.Set(jwk.KeyIDKey, kid)
			set := jwk.NewSet()
			set.AddKey(pubkey)

			_, err = jwt.Parse(signed, jwt.WithKeySet(set, jws.WithInferAlgorithmFromKey(true), jws.WithUseDefault(true)))
			if !assert.Error(t, err, `jwt.Parse should fail`) {
				return
			}
		})
		t.Run("UseDefault with a key set with 1 key", func(t *testing.T) {
			t.Parallel()
			pubkey, err := jwk.PublicKeyOf(key)
			if !assert.NoError(t, err) {
				return
			}

			pubkey.Set(jwk.AlgorithmKey, alg)
			pubkey.Set(jwk.KeyIDKey, kid)
			signedNoKid, err := jwt.Sign(t1, jwt.WithKey(alg, key))
			if err != nil {
				t.Fatal("Failed to sign JWT")
			}
			set := jwk.NewSet()
			set.AddKey(pubkey)
			t2, err := jwt.Parse(signedNoKid, jwt.WithKeySet(set, jws.WithUseDefault(true)))
			if !assert.NoError(t, err, `jwt.Parse with key set should succeed`) {
				return
			}
			if !assert.True(t, jwt.Equal(t1, t2), `t1 == t2`) {
				return
			}
		})
		t.Run("UseDefault with multiple keys should fail", func(t *testing.T) {
			t.Parallel()
			pubkey1, err := jwk.FromRaw(&key.PublicKey)
			if !assert.NoError(t, err) {
				return
			}
			pubkey2, err := jwk.FromRaw(&key.PublicKey)
			if !assert.NoError(t, err) {
				return
			}

			pubkey1.Set(jwk.KeyIDKey, kid)
			pubkey2.Set(jwk.KeyIDKey, "test-jwt-parse-verify-kid-2")
			signedNoKid, err := jwt.Sign(t1, jwt.WithKey(alg, key))
			if err != nil {
				t.Fatal("Failed to sign JWT")
			}
			set := jwk.NewSet()
			set.AddKey(pubkey1)
			set.AddKey(pubkey2)
			_, err = jwt.Parse(signedNoKid, jwt.WithKeySet(set, jws.WithUseDefault(true)))
			if !assert.Error(t, err, `jwt.Parse should fail`) {
				return
			}
		})
		// This is a test to check if we allow alg: none in the protected header section.
		// But in truth, since we delegate everything to jws.Verify anyways, it's really
		// a test to see if jws.Verify returns an error if alg: none is specified in the
		// header section. Move this test to jws if need be.
		t.Run("Check alg=none", func(t *testing.T) {
			t.Parallel()
			// Create a signed payload, but use alg=none
			_, payload, signature, err := jws.SplitCompact(signed)
			if !assert.NoError(t, err, `jws.SplitCompact should succeed`) {
				return
			}

			dummyHeader := jws.NewHeaders()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			for iter := hdrs.Iterate(ctx); iter.Next(ctx); {
				pair := iter.Pair()
				dummyHeader.Set(pair.Key.(string), pair.Value)
			}
			dummyHeader.Set(jws.AlgorithmKey, jwa.NoSignature)

			dummyMarshaled, err := json.Marshal(dummyHeader)
			if !assert.NoError(t, err, `json.Marshal should succeed`) {
				return
			}
			dummyEncoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(dummyMarshaled)))
			base64.RawURLEncoding.Encode(dummyEncoded, dummyMarshaled)

			signedButNot := bytes.Join([][]byte{dummyEncoded, payload, signature}, []byte{'.'})

			pubkey, err := jwk.FromRaw(&key.PublicKey)
			if !assert.NoError(t, err) {
				return
			}

			pubkey.Set(jwk.KeyIDKey, kid)

			set := jwk.NewSet()
			set.AddKey(pubkey)
			_, err = jwt.Parse(signedButNot, jwt.WithKeySet(set))
			// This should fail
			if !assert.Error(t, err, `jwt.Parse with key set + alg=none should fail`) {
				return
			}
		})
	})
}

func TestValidateClaims(t *testing.T) {
	t.Parallel()
	// GitHub issue #37: tokens are invalid in the second they are created (because Now() is not after IssuedAt())
	t.Run("Empty fields", func(t *testing.T) {
		token := jwt.New()

		if !assert.Error(t, jwt.Validate(token, jwt.WithIssuer("foo")), `token.Validate should fail`) {
			return
		}
		if !assert.Error(t, jwt.Validate(token, jwt.WithJwtID("foo")), `token.Validate should fail`) {
			return
		}
		if !assert.Error(t, jwt.Validate(token, jwt.WithSubject("foo")), `token.Validate should fail`) {
			return
		}
	})
	t.Run(jwt.IssuedAtKey+"+skew", func(t *testing.T) {
		t.Parallel()
		token := jwt.New()
		now := time.Now().UTC()
		token.Set(jwt.IssuedAtKey, now)

		const DefaultSkew = 0

		args := []jwt.ValidateOption{
			jwt.WithClock(jwt.ClockFunc(func() time.Time { return now })),
			jwt.WithAcceptableSkew(DefaultSkew),
		}

		if !assert.NoError(t, jwt.Validate(token, args...), "token.Validate should validate tokens in the same second they are created") {
			if now.Equal(token.IssuedAt()) {
				t.Errorf("iat claim failed: iat == now")
			}
			return
		}
	})
}

const aLongLongTimeAgo = 233431200
const aLongLongTimeAgoString = "233431200"

func TestUnmarshal(t *testing.T) {
	t.Parallel()
	testcases := []struct {
		Title        string
		Source       string
		Expected     func() jwt.Token
		ExpectedJSON string
	}{
		{
			Title:  "single aud",
			Source: `{"aud":"foo"}`,
			Expected: func() jwt.Token {
				t := jwt.New()
				t.Set("aud", "foo")
				return t
			},
			ExpectedJSON: `{"aud":["foo"]}`,
		},
		{
			Title:  "multiple aud's",
			Source: `{"aud":["foo","bar"]}`,
			Expected: func() jwt.Token {
				t := jwt.New()
				t.Set("aud", []string{"foo", "bar"})
				return t
			},
			ExpectedJSON: `{"aud":["foo","bar"]}`,
		},
		{
			Title:  "issuedAt",
			Source: `{"` + jwt.IssuedAtKey + `":` + aLongLongTimeAgoString + `}`,
			Expected: func() jwt.Token {
				t := jwt.New()
				t.Set(jwt.IssuedAtKey, aLongLongTimeAgo)
				return t
			},
			ExpectedJSON: `{"` + jwt.IssuedAtKey + `":` + aLongLongTimeAgoString + `}`,
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Title, func(t *testing.T) {
			t.Parallel()
			token := jwt.New()
			if !assert.NoError(t, json.Unmarshal([]byte(tc.Source), &token), `json.Unmarshal should succeed`) {
				return
			}
			if !assert.Equal(t, tc.Expected(), token, `token should match expected value`) {
				return
			}

			var buf bytes.Buffer
			if !assert.NoError(t, json.NewEncoder(&buf).Encode(token), `json.Marshal should succeed`) {
				return
			}
			if !assert.Equal(t, tc.ExpectedJSON, strings.TrimSpace(buf.String()), `json should match`) {
				return
			}
		})
	}
}

func TestGH52(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	t.Parallel()
	priv, err := jwxtest.GenerateEcdsaKey(jwa.P521)
	if !assert.NoError(t, err) {
		return
	}

	pub := &priv.PublicKey
	if !assert.NoError(t, err) {
		return
	}
	const max = 100
	var wg sync.WaitGroup
	wg.Add(max)
	for i := 0; i < max; i++ {
		// Do not use t.Run here as it will clutter up the outpuA
		go func(t *testing.T, priv *ecdsa.PrivateKey, i int) {
			defer wg.Done()
			tok := jwt.New()

			s, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, priv))
			if !assert.NoError(t, err) {
				return
			}

			if _, err = jws.Verify(s, jws.WithKey(jwa.ES256, pub)); !assert.NoError(t, err, `test should pass (run %d)`, i) {
				return
			}
		}(t, priv, i)
	}
	wg.Wait()
}

func TestUnmarshalJSON(t *testing.T) {
	t.Parallel()
	t.Run("Unmarshal audience with multiple values", func(t *testing.T) {
		t.Parallel()
		t1 := jwt.New()
		if !assert.NoError(t, json.Unmarshal([]byte(`{"aud":["foo", "bar", "baz"]}`), &t1), `jwt.Parse should succeed`) {
			return
		}
		aud, ok := t1.Get(jwt.AudienceKey)
		if !assert.True(t, ok, `jwt.Get(jwt.AudienceKey) should succeed`) {
			t.Logf("%#v", t1)
			return
		}

		if !assert.Equal(t, aud.([]string), []string{"foo", "bar", "baz"}, "audience should match. got %v", aud) {
			return
		}
	})
}

func TestSignErrors(t *testing.T) {
	t.Parallel()
	priv, err := jwxtest.GenerateEcdsaKey(jwa.P521)
	if !assert.NoError(t, err, `jwxtest.GenerateEcdsaKey should succeed`) {
		return
	}

	tok := jwt.New()
	_, err = jwt.Sign(tok, jwt.WithKey(jwa.SignatureAlgorithm("BOGUS"), priv))
	if !assert.Error(t, err) {
		return
	}

	if !assert.Contains(t, err.Error(), `unsupported signature algorithm "BOGUS"`) {
		return
	}

	_, err = jwt.Sign(tok, jwt.WithKey(jwa.ES256, nil))
	if !assert.Error(t, err) {
		return
	}

	if !assert.Contains(t, err.Error(), "missing private key") {
		return
	}
}

func TestSignJWK(t *testing.T) {
	t.Parallel()
	priv, err := jwxtest.GenerateRsaKey()
	assert.Nil(t, err)

	key, err := jwk.FromRaw(priv)
	assert.Nil(t, err)

	key.Set(jwk.KeyIDKey, "test")
	key.Set(jwk.AlgorithmKey, jwa.RS256)

	tok := jwt.New()
	signed, err := jwt.Sign(tok, jwt.WithKey(key.Algorithm(), key))
	assert.Nil(t, err)

	header, err := jws.ParseString(string(signed))
	assert.Nil(t, err)

	signatures := header.LookupSignature("test")
	assert.Len(t, signatures, 1)
}

func getJWTHeaders(jwt []byte) (jws.Headers, error) {
	msg, err := jws.Parse(jwt)
	if err != nil {
		return nil, err
	}
	return msg.Signatures()[0].ProtectedHeaders(), nil
}

func TestSignTyp(t *testing.T) {
	t.Parallel()
	key, err := jwxtest.GenerateRsaKey()
	if !assert.NoError(t, err) {
		return
	}

	t.Run(`"typ" header parameter should be set to JWT by default`, func(t *testing.T) {
		t.Parallel()
		t1 := jwt.New()
		signed, err := jwt.Sign(t1, jwt.WithKey(jwa.RS256, key))
		if !assert.NoError(t, err) {
			return
		}
		got, err := getJWTHeaders(signed)
		if !assert.NoError(t, err) {
			return
		}
		if !assert.Equal(t, `JWT`, got.Type(), `"typ" header parameter should be set to JWT`) {
			return
		}
	})

	t.Run(`"typ" header parameter should be customizable by WithHeaders`, func(t *testing.T) {
		t.Parallel()
		t1 := jwt.New()
		hdrs := jws.NewHeaders()
		hdrs.Set(`typ`, `custom-typ`)
		signed, err := jwt.Sign(t1, jwt.WithKey(jwa.RS256, key, jws.WithProtectedHeaders(hdrs)))
		if !assert.NoError(t, err) {
			return
		}
		got, err := getJWTHeaders(signed)
		if !assert.NoError(t, err) {
			return
		}
		if !assert.Equal(t, `custom-typ`, got.Type(), `"typ" header parameter should be set to the custom value`) {
			return
		}
	})
}

func TestReadFile(t *testing.T) {
	t.Parallel()

	f, err := os.CreateTemp("", "test-read-file-*.jwt")
	if !assert.NoError(t, err, `os.CreateTemp should succeed`) {
		return
	}
	defer f.Close()

	token := jwt.New()
	token.Set(jwt.IssuerKey, `lestrrat`)
	if !assert.NoError(t, json.NewEncoder(f).Encode(token), `json.NewEncoder.Encode should succeed`) {
		return
	}

	if _, err := jwt.ReadFile(f.Name(), jwt.WithVerify(false), jwt.WithValidate(true), jwt.WithIssuer("lestrrat")); !assert.NoError(t, err, `jwt.ReadFile should succeed`) {
		return
	}
	if _, err := jwt.ReadFile(f.Name(), jwt.WithVerify(false), jwt.WithValidate(true), jwt.WithIssuer("lestrrrrrat")); !assert.Error(t, err, `jwt.ReadFile should fail`) {
		return
	}
}

func TestCustomField(t *testing.T) {
	// XXX has global effect!!!
	jwt.RegisterCustomField(`x-birthday`, time.Time{})
	defer jwt.RegisterCustomField(`x-birthday`, nil)

	expected := time.Date(2015, 11, 4, 5, 12, 52, 0, time.UTC)
	bdaybytes, _ := expected.MarshalText() // RFC3339

	var b strings.Builder
	b.WriteString(`{"iss": "github.com/lesstrrat-go/jwx", "x-birthday": "`)
	b.Write(bdaybytes)
	b.WriteString(`"}`)
	src := b.String()

	t.Run("jwt.Parse", func(t *testing.T) {
		token, err := jwt.ParseInsecure([]byte(src))
		if !assert.NoError(t, err, `jwt.Parse should succeed`) {
			t.Logf("%q", src)
			return
		}

		v, ok := token.Get(`x-birthday`)
		if !assert.True(t, ok, `token.Get("x-birthday") should succeed`) {
			return
		}

		if !assert.Equal(t, expected, v, `values should match`) {
			return
		}
	})
	t.Run("json.Unmarshal", func(t *testing.T) {
		token := jwt.New()
		if !assert.NoError(t, json.Unmarshal([]byte(src), token), `json.Unmarshal should succeed`) {
			return
		}

		v, ok := token.Get(`x-birthday`)
		if !assert.True(t, ok, `token.Get("x-birthday") should succeed`) {
			return
		}

		if !assert.Equal(t, expected, v, `values should match`) {
			return
		}
	})
}

func TestParseRequest(t *testing.T) {
	const u = "https://github.com/lestrrat-gow/jwx/jwt"

	privkey, _ := jwxtest.GenerateEcdsaJwk()
	privkey.Set(jwk.AlgorithmKey, jwa.ES256)
	privkey.Set(jwk.KeyIDKey, `my-awesome-key`)
	pubkey, _ := jwk.PublicKeyOf(privkey)
	pubkey.Set(jwk.AlgorithmKey, jwa.ES256)

	tok := jwt.New()
	tok.Set(jwt.IssuerKey, u)
	tok.Set(jwt.IssuedAtKey, time.Now().Round(0))

	signed, _ := jwt.Sign(tok, jwt.WithKey(jwa.ES256, privkey))

	testcases := []struct {
		Request func() *http.Request
		Parse   func(*http.Request) (jwt.Token, error)
		Name    string
		Error   bool
	}{
		{
			Name: "Token not present (w/ multiple options)",
			Request: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, u, nil)
			},
			Parse: func(req *http.Request) (jwt.Token, error) {
				return jwt.ParseRequest(req,
					jwt.WithHeaderKey("Authorization"),
					jwt.WithHeaderKey("x-authorization"),
					jwt.WithFormKey("access_token"),
					jwt.WithFormKey("token"),
					jwt.WithKey(jwa.ES256, pubkey))
			},
			Error: true,
		},
		{
			Name: "Token not present (w/o options)",
			Request: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, u, nil)
			},
			Parse: func(req *http.Request) (jwt.Token, error) {
				return jwt.ParseRequest(req, jwt.WithKey(jwa.ES256, pubkey))
			},
			Error: true,
		},
		{
			Name: "Token in Authorization header (w/o extra options)",
			Request: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, u, nil)
				req.Header.Add("Authorization", "Bearer "+string(signed))
				return req
			},
			Parse: func(req *http.Request) (jwt.Token, error) {
				return jwt.ParseRequest(req, jwt.WithKey(jwa.ES256, pubkey))
			},
		},
		{
			Name: "Token in Authorization header (w/o extra options, using jwk.Set)",
			Request: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, u, nil)
				req.Header.Add("Authorization", "Bearer "+string(signed))
				return req
			},
			Parse: func(req *http.Request) (jwt.Token, error) {
				set := jwk.NewSet()
				set.AddKey(pubkey)
				return jwt.ParseRequest(req, jwt.WithKeySet(set))
			},
		},
		{
			Name: "Token in Authorization header but we specified another header key",
			Request: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, u, nil)
				req.Header.Add("Authorization", "Bearer "+string(signed))
				return req
			},
			Parse: func(req *http.Request) (jwt.Token, error) {
				return jwt.ParseRequest(req, jwt.WithHeaderKey("x-authorization"), jwt.WithKey(jwa.ES256, pubkey))
			},
			Error: true,
		},
		{
			Name: "Token in x-authorization header (w/ option)",
			Request: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, u, nil)
				req.Header.Add("x-authorization", string(signed))
				return req
			},
			Parse: func(req *http.Request) (jwt.Token, error) {
				return jwt.ParseRequest(req, jwt.WithHeaderKey("x-authorization"), jwt.WithKey(jwa.ES256, pubkey))
			},
		},
		{
			Name: "Invalid token in x-authorization header",
			Request: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, u, nil)
				req.Header.Add("x-authorization", string(signed)+"foobarbaz")
				return req
			},
			Parse: func(req *http.Request) (jwt.Token, error) {
				return jwt.ParseRequest(req, jwt.WithHeaderKey("x-authorization"), jwt.WithKey(jwa.ES256, pubkey))
			},
			Error: true,
		},
		{
			Name: "Token in access_token form field (w/ option)",
			Request: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, u, nil)
				// for whatever reason, I can't populate req.Body and get this to work
				// so populating req.Form directly instead
				req.Form = url.Values{}
				req.Form.Add("access_token", string(signed))
				return req
			},
			Parse: func(req *http.Request) (jwt.Token, error) {
				return jwt.ParseRequest(req, jwt.WithFormKey("access_token"), jwt.WithKey(jwa.ES256, pubkey))
			},
		},
		{
			Name: "Token in access_token form field (w/o option)",
			Request: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, u, nil)
				// for whatever reason, I can't populate req.Body and get this to work
				// so populating req.Form directly instead
				req.Form = url.Values{}
				req.Form.Add("access_token", string(signed))
				return req
			},
			Parse: func(req *http.Request) (jwt.Token, error) {
				return jwt.ParseRequest(req, jwt.WithKey(jwa.ES256, pubkey))
			},
			Error: true,
		},
		{
			Name: "Invalid token in access_token form field",
			Request: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, u, nil)
				// for whatever reason, I can't populate req.Body and get this to work
				// so populating req.Form directly instead
				req.Form = url.Values{}
				req.Form.Add("access_token", string(signed)+"foobarbarz")
				return req
			},
			Parse: func(req *http.Request) (jwt.Token, error) {
				return jwt.ParseRequest(req, jwt.WithKey(jwa.ES256, pubkey), jwt.WithFormKey("access_token"))
			},
			Error: true,
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			got, err := tc.Parse(tc.Request())
			if tc.Error {
				t.Logf("%s", err)
				assert.Error(t, err, `tc.Parse should fail`)
				return
			}

			if !assert.NoError(t, err, `tc.Parse should succeed`) {
				return
			}

			if !assert.True(t, jwt.Equal(tok, got), `tokens should match`) {
				{
					buf, _ := json.MarshalIndent(tok, "", "  ")
					t.Logf("expected: %s", buf)
				}
				{
					buf, _ := json.MarshalIndent(got, "", "  ")
					t.Logf("got: %s", buf)
				}
				return
			}
		})
	}
}

func TestGHIssue368(t *testing.T) {
	// DO NOT RUN THIS IN PARALLEL
	t.Run("Per-object control of flatten audience", func(t *testing.T) {
		for _, globalFlatten := range []bool{true, false} {
			globalFlatten := globalFlatten
			for _, perObjectFlatten := range []bool{true, false} {
				perObjectFlatten := perObjectFlatten
				// per-object settings always wins
				t.Run(fmt.Sprintf("Global=%t, Per-Object=%t", globalFlatten, perObjectFlatten), func(t *testing.T) {
					defer jwt.Settings(jwt.WithFlattenAudience(false))
					jwt.Settings(jwt.WithFlattenAudience(globalFlatten))

					tok, _ := jwt.NewBuilder().
						Audience([]string{"hello"}).
						Build()

					if perObjectFlatten {
						tok.Options().Enable(jwt.FlattenAudience)
					} else {
						tok.Options().Disable(jwt.FlattenAudience)
					}
					buf, err := json.MarshalIndent(tok, "", "  ")
					if !assert.NoError(t, err, `json.MarshalIndent should succeed`) {
						return
					}

					var expected string
					if perObjectFlatten {
						expected = `{
  "aud": "hello"
}`
					} else {
						expected = `{
  "aud": [
    "hello"
  ]
}`
					}

					if !assert.Equal(t, expected, string(buf), `output should match`) {
						return
					}
				})
			}
		}
	})

	for _, flatten := range []bool{true, false} {
		flatten := flatten
		t.Run(fmt.Sprintf("Test serialization (WithFlattenAudience(%t))", flatten), func(t *testing.T) {
			jwt.Settings(jwt.WithFlattenAudience(flatten))

			t.Run("Single Key", func(t *testing.T) {
				tok := jwt.New()
				_ = tok.Set(jwt.AudienceKey, "hello")

				buf, err := json.MarshalIndent(tok, "", "  ")
				if !assert.NoError(t, err, `json.MarshalIndent should succeed`) {
					return
				}

				var expected string
				if flatten {
					expected = `{
  "aud": "hello"
}`
				} else {
					expected = `{
  "aud": [
    "hello"
  ]
}`
				}

				if !assert.Equal(t, expected, string(buf), `output should match`) {
					return
				}
			})
			t.Run("Multiple Keys", func(t *testing.T) {
				tok, err := jwt.NewBuilder().
					Audience([]string{"hello", "world"}).
					Build()
				if !assert.NoError(t, err, `jwt.Builder should succeed`) {
					return
				}

				buf, err := json.MarshalIndent(tok, "", "  ")
				if !assert.NoError(t, err, `json.MarshalIndent should succeed`) {
					return
				}

				const expected = `{
  "aud": [
    "hello",
    "world"
  ]
}`

				if !assert.Equal(t, expected, string(buf), `output should match`) {
					return
				}
			})
		})
	}
}

func TestGH375(t *testing.T) {
	key, err := jwxtest.GenerateRsaJwk()
	if !assert.NoError(t, err, `jwxtest.GenerateRsaJwk should succeed`) {
		return
	}
	key.Set(jwk.KeyIDKey, `test`)

	token, err := jwt.NewBuilder().
		Issuer(`foobar`).
		Build()
	if !assert.NoError(t, err, `jwt.Builder should succeed`) {
		return
	}

	signAlg := jwa.RS512
	signed, err := jwt.Sign(token, jwt.WithKey(signAlg, key))
	if !assert.NoError(t, err, `jwt.Sign should succeed`) {
		return
	}

	verifyKey, err := jwk.PublicKeyOf(key)
	if !assert.NoError(t, err, `jwk.PublicKeyOf should succeed`) {
		return
	}

	verifyKey.Set(jwk.KeyIDKey, `test`)
	verifyKey.Set(jwk.AlgorithmKey, jwa.RS256) // != jwa.RS512

	ks := jwk.NewSet()
	ks.AddKey(verifyKey)

	_, err = jwt.Parse(signed, jwt.WithKeySet(ks))
	if !assert.Error(t, err, `jwt.Parse should fail`) {
		return
	}
}

type Claim struct {
	Foo string
	Bar int
}

func TestJWTParseWithTypedClaim(t *testing.T) {
	testcases := []struct {
		Name        string
		Options     []jwt.ParseOption
		PostProcess func(*testing.T, interface{}) (*Claim, error)
	}{
		{
			Name:    "Basic",
			Options: []jwt.ParseOption{jwt.WithTypedClaim("typed-claim", Claim{})},
			PostProcess: func(t *testing.T, claim interface{}) (*Claim, error) {
				t.Helper()
				v, ok := claim.(Claim)
				if !ok {
					return nil, fmt.Errorf(`claim value should be of type "Claim", but got %T`, claim)
				}
				return &v, nil
			},
		},
		{
			Name:    "json.RawMessage",
			Options: []jwt.ParseOption{jwt.WithTypedClaim("typed-claim", json.RawMessage{})},
			PostProcess: func(t *testing.T, claim interface{}) (*Claim, error) {
				t.Helper()
				v, ok := claim.(json.RawMessage)
				if !ok {
					return nil, fmt.Errorf(`claim value should be of type "json.RawMessage", but got %T`, claim)
				}

				var c Claim
				if err := json.Unmarshal(v, &c); err != nil {
					return nil, fmt.Errorf(`json.Unmarshal failed: %w`, err)
				}

				return &c, nil
			},
		},
	}

	expected := &Claim{Foo: "Foo", Bar: 0xdeadbeef}
	key, err := jwxtest.GenerateRsaKey()
	if !assert.NoError(t, err, `jwxtest.GenerateRsaKey should succeed`) {
		return
	}

	var signed []byte
	{
		token := jwt.New()
		if !assert.NoError(t, token.Set("typed-claim", expected), `expected.Set should succeed`) {
			return
		}
		v, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, key))
		if !assert.NoError(t, err, `jwt.Sign should succeed`) {
			return
		}
		signed = v
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			options := append(tc.Options, jwt.WithVerify(false))
			got, err := jwt.Parse(signed, options...)
			if !assert.NoError(t, err, `jwt.Parse should succeed`) {
				return
			}

			v, ok := got.Get("typed-claim")
			if !assert.True(t, ok, `got.Get() should succeed`) {
				return
			}
			claim, err := tc.PostProcess(t, v)
			if !assert.NoError(t, err, `tc.PostProcess should succeed`) {
				return
			}

			if !assert.Equal(t, claim, expected, `claim should match expected value`) {
				return
			}
		})
	}
}

func TestGH393(t *testing.T) {
	t.Run("Non-existent required claims", func(t *testing.T) {
		tok := jwt.New()
		if !assert.Error(t, jwt.Validate(tok, jwt.WithRequiredClaim(jwt.IssuedAtKey)), `jwt.Validate should fail`) {
			return
		}
	})
	t.Run("exp - iat < WithMaxDelta(10 secs)", func(t *testing.T) {
		now := time.Now()
		tok, err := jwt.NewBuilder().
			IssuedAt(now).
			Expiration(now.Add(5 * time.Second)).
			Build()
		if !assert.NoError(t, err, `jwt.Builder should succeed`) {
			return
		}

		if !assert.Error(t, jwt.Validate(tok, jwt.WithMaxDelta(2*time.Second, jwt.ExpirationKey, jwt.IssuedAtKey)), `jwt.Validate should fail`) {
			return
		}

		if !assert.NoError(t, jwt.Validate(tok, jwt.WithMaxDelta(10*time.Second, jwt.ExpirationKey, jwt.IssuedAtKey)), `jwt.Validate should succeed`) {
			return
		}
	})
	t.Run("iat - exp (5 secs) < WithMinDelta(10 secs)", func(t *testing.T) {
		now := time.Now()
		tok, err := jwt.NewBuilder().
			IssuedAt(now).
			Expiration(now.Add(5 * time.Second)).
			Build()
		if !assert.NoError(t, err, `jwt.Builder should succeed`) {
			return
		}

		if !assert.Error(t, jwt.Validate(tok, jwt.WithMinDelta(10*time.Second, jwt.ExpirationKey, jwt.IssuedAtKey)), `jwt.Validate should fail`) {
			return
		}
	})
	t.Run("iat - exp (5 secs) > WithMinDelta(10 secs)", func(t *testing.T) {
		now := time.Now()
		tok, err := jwt.NewBuilder().
			IssuedAt(now).
			Expiration(now.Add(5 * time.Second)).
			Build()
		if !assert.NoError(t, err, `jwt.Builder should succeed`) {
			return
		}

		if !assert.NoError(t, jwt.Validate(tok, jwt.WithMinDelta(10*time.Second, jwt.ExpirationKey, jwt.IssuedAtKey), jwt.WithAcceptableSkew(5*time.Second)), `jwt.Validate should succeed`) {
			return
		}
	})
	t.Run("now - iat < WithMaxDelta(10 secs)", func(t *testing.T) {
		now := time.Now()
		tok, err := jwt.NewBuilder().
			IssuedAt(now).
			Build()
		if !assert.NoError(t, err, `jwt.Builder should succeed`) {
			return
		}

		if !assert.NoError(t, jwt.Validate(tok, jwt.WithMaxDelta(10*time.Second, "", jwt.IssuedAtKey), jwt.WithClock(jwt.ClockFunc(func() time.Time { return now.Add(5 * time.Second) }))), `jwt.Validate should succeed`) {
			return
		}
	})
	t.Run("invalid claim name (c1)", func(t *testing.T) {
		now := time.Now()
		tok, err := jwt.NewBuilder().
			Claim("foo", now).
			Expiration(now.Add(5 * time.Second)).
			Build()
		if !assert.NoError(t, err, `jwt.Builder should succeed`) {
			return
		}

		if !assert.Error(t, jwt.Validate(tok, jwt.WithMinDelta(10*time.Second, jwt.ExpirationKey, "foo"), jwt.WithAcceptableSkew(5*time.Second)), `jwt.Validate should fail`) {
			return
		}
	})
	t.Run("invalid claim name (c2)", func(t *testing.T) {
		now := time.Now()
		tok, err := jwt.NewBuilder().
			Claim("foo", now.Add(5*time.Second)).
			IssuedAt(now).
			Build()
		if !assert.NoError(t, err, `jwt.Builder should succeed`) {
			return
		}

		if !assert.Error(t, jwt.Validate(tok, jwt.WithMinDelta(10*time.Second, "foo", jwt.IssuedAtKey), jwt.WithAcceptableSkew(5*time.Second)), `jwt.Validate should fail`) {
			return
		}
	})

	// Following tests deviate a little from the original issue, but
	// since they were added for the same issue, we just bundle the
	// tests together
	t.Run(`WithRequiredClaim fails for non-existent claim`, func(t *testing.T) {
		tok := jwt.New()
		if !assert.Error(t, jwt.Validate(tok, jwt.WithRequiredClaim("foo")), `jwt.Validate should fail`) {
			return
		}
	})
	t.Run(`WithRequiredClaim succeeds for existing claim`, func(t *testing.T) {
		tok, err := jwt.NewBuilder().
			Claim(`foo`, 1).
			Build()
		if !assert.NoError(t, err, `jwt.Builder should succeed`) {
			return
		}
		if !assert.NoError(t, jwt.Validate(tok, jwt.WithRequiredClaim("foo")), `jwt.Validate should fail`) {
			return
		}
	})
}

func TestGH430(t *testing.T) {
	t1 := jwt.New()
	err := t1.Set("payload", map[string]interface{}{
		"name": "someone",
	})
	if !assert.NoError(t, err, `t1.Set should succeed`) {
		return
	}

	key := []byte("secret")
	signed, err := jwt.Sign(t1, jwt.WithKey(jwa.HS256, key))
	if !assert.NoError(t, err, `jwt.Sign should succeed`) {
		return
	}

	if _, err = jwt.Parse(signed, jwt.WithKey(jwa.HS256, key)); !assert.NoError(t, err, `jwt.Parse should succeed`) {
		return
	}
}

func TestGH706(t *testing.T) {
	err := jwt.Validate(jwt.New(), jwt.WithRequiredClaim("foo"))
	if !assert.True(t, jwt.IsValidationError(err), `error should be a validation error`) {
		return
	}

	if !assert.ErrorIs(t, err, jwt.ErrRequiredClaim(), `jwt.Validate should fail`) {
		return
	}
}

func TestBenHigginsByPassRegression(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	// Test if an access token JSON payload parses when provided directly
	//
	// The JSON below is slightly modified example payload from:
	// https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-access-token.html

	// Case 1: add "aud", and adjust exp to be valid
	// Case 2: do not add "aud", adjust exp

	exp := strconv.Itoa(int(time.Now().Unix()) + 1000)
	const tmpl = `{%s
    "sub": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "device_key": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "cognito:groups": ["admin"],
    "token_use": "access",
    "scope": "aws.cognito.signin.user.admin",
    "auth_time": 1562190524,
    "iss": "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_example",
    "exp": %s,
    "iat": 1562190524,
    "origin_jti": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "jti": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "client_id": "57cbishk4j24pabc1234567890",
    "username": "janedoe@example.com"
  }`

	testcases := [][]byte{
		[]byte(fmt.Sprintf(tmpl, `"aud": ["test"],`, exp)),
		[]byte(fmt.Sprintf(tmpl, ``, exp)),
	}

	for _, tc := range testcases {
		for _, pedantic := range []bool{true, false} {
			_, err = jwt.Parse(
				tc,
				jwt.WithValidate(true),
				jwt.WithPedantic(pedantic),
				jwt.WithKey(jwa.RS256, &key.PublicKey),
			)
			t.Logf("%s", err)
			if !assert.Error(t, err, `jwt.Parse should fail`) {
				return
			}
		}
	}
}

func TestVerifyAuto(t *testing.T) {
	key, err := jwxtest.GenerateRsaJwk()
	if !assert.NoError(t, err, `jwxtest.GenerateRsaJwk should succeed`) {
		return
	}

	key.Set(jwk.KeyIDKey, `my-awesome-key`)

	pubkey, err := jwk.PublicKeyOf(key)
	if !assert.NoError(t, err, `jwk.PublicKeyOf should succeed`) {
		return
	}
	set := jwk.NewSet()
	set.AddKey(pubkey)
	backoffCount := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get(`type`) {
		case "backoff":
			backoffCount++
			if backoffCount == 1 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(set)
	}))
	defer srv.Close()

	tok, err := jwt.NewBuilder().
		Claim(jwt.IssuerKey, `https://github.com/lestrrat-go/jwx/v2`).
		Claim(jwt.SubjectKey, `jku-test`).
		Build()

	if !assert.NoError(t, err, `jwt.NewBuilder.Build() should succeed`) {
		return
	}

	hdrs := jws.NewHeaders()
	hdrs.Set(jws.JWKSetURLKey, srv.URL)

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, key, jws.WithProtectedHeaders(hdrs)))
	if !assert.NoError(t, err, `jwt.Sign() should succeed`) {
		return
	}

	wl := jwk.NewMapWhitelist().
		Add(srv.URL)

	parsed, err := jwt.Parse(signed, jwt.WithVerifyAuto(nil, jwk.WithFetchWhitelist(wl), jwk.WithHTTPClient(srv.Client())))
	if !assert.NoError(t, err, `jwt.Parse should succeed`) {
		return
	}

	if !assert.True(t, jwt.Equal(tok, parsed), `tokens should be equal`) {
		return
	}

	_, err = jwt.Parse(signed, jwt.WithVerifyAuto(nil))
	if !assert.Error(t, err, `jwt.Parse should fail`) {
		return
	}
	wl = jwk.NewMapWhitelist().
		Add(`https://github.com/lestrrat-go/jwx/v2`)
	_, err = jwt.Parse(signed, jwt.WithVerifyAuto(nil, jwk.WithFetchWhitelist(wl)))
	if !assert.Error(t, err, `jwt.Parse should fail`) {
		return
	}

	// now with Cache
	c := jwk.NewCache(context.TODO())
	parsed, err = jwt.Parse(signed,
		jwt.WithVerifyAuto(
			jwk.FetchFunc(func(ctx context.Context, u string, options ...jwk.FetchOption) (jwk.Set, error) {
				var registeropts []jwk.RegisterOption
				// jwk.FetchOption is also an CacheOption, but the container
				// doesn't match the signature... so... we need to convert them...
				for _, option := range options {
					registeropts = append(registeropts, option)
				}
				c.Register(u, registeropts...)
				return c.Get(ctx, u)
			}),
			jwk.WithHTTPClient(srv.Client()),
			jwk.WithFetchWhitelist(jwk.InsecureWhitelist{}),
		),
	)
	if !assert.NoError(t, err, `jwt.Parse should succeed`) {
		return
	}

	if !assert.True(t, jwt.Equal(tok, parsed), `tokens should be equal`) {
		return
	}
}

func TestSerializer(t *testing.T) {
	t.Run(`Invalid sign suboption`, func(t *testing.T) {
		_, err := jwt.NewSerializer().
			Sign(jwt.WithKey(jwa.HS256, []byte("abracadabra"), jwe.WithCompress(jwa.Deflate))).
			Serialize(jwt.New())
		if !assert.Error(t, err, `Serialize() should fail`) {
			return
		}
	})
	t.Run(`Invalid SignatureAglrotihm`, func(t *testing.T) {
		_, err := jwt.NewSerializer().
			Encrypt(jwt.WithKey(jwa.A256KW, []byte("abracadabra"))).
			Serialize(jwt.New())
		if !assert.Error(t, err, `Serialize() should succeedl`) {
			return
		}
	})
	t.Run(`Invalid encrypt suboption`, func(t *testing.T) {
		_, err := jwt.NewSerializer().
			Encrypt(jwt.WithKey(jwa.A256KW, []byte("abracadabra"), jws.WithPretty(true))).
			Serialize(jwt.New())
		if !assert.Error(t, err, `Serialize() should fail`) {
			return
		}
	})
	t.Run(`Invalid KeyEncryptionAglrotihm`, func(t *testing.T) {
		_, err := jwt.NewSerializer().
			Encrypt(jwt.WithKey(jwa.HS256, []byte("abracadabra"))).
			Serialize(jwt.New())
		if !assert.Error(t, err, `Serialize() should succeedl`) {
			return
		}
	})
}

func TestFractional(t *testing.T) {
	t.Run("FormatPrecision", func(t *testing.T) {
		var nd types.NumericDate
		jwt.Settings(jwt.WithNumericDateParsePrecision(int(types.MaxPrecision)))
		s := fmt.Sprintf("%d.100000001", aLongLongTimeAgo)
		_ = nd.Accept(s)
		jwt.Settings(jwt.WithNumericDateParsePrecision(0))
		testcases := []struct {
			Input     types.NumericDate
			Expected  string
			Precision int
		}{
			{
				Input:    nd,
				Expected: fmt.Sprintf(`%d`, aLongLongTimeAgo),
			},
			{
				Input:    types.NumericDate{Time: time.Unix(0, 1).UTC()},
				Expected: "0",
			},
			{
				Input:     types.NumericDate{Time: time.Unix(0, 1).UTC()},
				Precision: 9,
				Expected:  "0.000000001",
			},
			{
				Input:     types.NumericDate{Time: time.Unix(0, 100000000).UTC()},
				Precision: 9,
				Expected:  "0.100000000",
			},
		}

		for i := 1; i <= int(types.MaxPrecision); i++ {
			fractional := (fmt.Sprintf(`%d`, 100000001))[:i]
			testcases = append(testcases, struct {
				Input     types.NumericDate
				Expected  string
				Precision int
			}{
				Input:     nd,
				Precision: i,
				Expected:  fmt.Sprintf(`%d.%s`, aLongLongTimeAgo, fractional),
			})
		}

		for _, tc := range testcases {
			tc := tc
			t.Run(fmt.Sprintf("%s (precision=%d)", tc.Input, tc.Precision), func(t *testing.T) {
				jwt.Settings(jwt.WithNumericDateFormatPrecision(tc.Precision))
				require.Equal(t, tc.Expected, tc.Input.String())
			})
		}
		jwt.Settings(jwt.WithNumericDateFormatPrecision(0))
	})
	t.Run("ParsePrecision", func(t *testing.T) {
		const template = `{"iat":"%s"}`

		testcases := []struct {
			Input     string
			Expected  time.Time
			Precision int
		}{
			{
				Input:    "0",
				Expected: time.Unix(0, 0).UTC(),
			},
			{
				Input:    "0.000000001",
				Expected: time.Unix(0, 0).UTC(),
			},
			{
				Input:    fmt.Sprintf("%d.111111111", aLongLongTimeAgo),
				Expected: time.Unix(aLongLongTimeAgo, 0).UTC(),
			},
			{
				// Max precision
				Input:     fmt.Sprintf("%d.100000001", aLongLongTimeAgo),
				Precision: int(types.MaxPrecision),
				Expected:  time.Unix(aLongLongTimeAgo, 100000001).UTC(),
			},
		}

		for i := 1; i < int(types.MaxPrecision); i++ {
			testcases = append(testcases, struct {
				Input     string
				Expected  time.Time
				Precision int
			}{
				Input:     fmt.Sprintf("%d.100000001", aLongLongTimeAgo),
				Precision: i,
				Expected:  time.Unix(aLongLongTimeAgo, 100000000).UTC(),
			})
		}

		for _, tc := range testcases {
			tc := tc
			t.Run(fmt.Sprintf("%s (precision=%d)", tc.Input, tc.Precision), func(t *testing.T) {
				jwt.Settings(jwt.WithNumericDateParsePrecision(tc.Precision))
				tok, err := jwt.Parse(
					[]byte(fmt.Sprintf(template, tc.Input)),
					jwt.WithVerify(false),
					jwt.WithValidate(false),
				)
				require.NoError(t, err, `jwt.Parse should succeed`)

				require.Equal(t, tc.Expected, tok.IssuedAt(), `iat should match`)
			})
		}
		jwt.Settings(jwt.WithNumericDateParsePrecision(0))
	})
}

func TestGH836(t *testing.T) {
	// tests on TokenOptionSet are found elsewhere.

	t1 := jwt.New()
	t1.Options().Enable(jwt.FlattenAudience)

	require.True(t, t1.Options().IsEnabled(jwt.FlattenAudience), `flag should be enabled`)

	t2, err := t1.Clone()
	require.NoError(t, err, `t1.Clone should succeed`)

	require.True(t, t2.Options().IsEnabled(jwt.FlattenAudience), `cloned token should have same settings`)

	t2.Options().Disable(jwt.FlattenAudience)
	require.True(t, t1.Options().IsEnabled(jwt.FlattenAudience), `flag should be enabled (t2.Options should have no effect on t1.Options)`)
}

func TestGH850(t *testing.T) {
	var testToken = `eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNjY2MDkxMzczLCJmb28iOiJiYXIifQ.3GWevx1z2_uCBB9Vj-D0rsT_CMsMeP9GP2rEqGDWpesoG8nHEjAXJOEQV1jOVkkCtTnS18JhcQdb7dW4i-zmqg.trailing-rubbish`

	_, err := jwt.Parse([]byte(testToken), jwt.WithVerify(false))
	require.True(t, errors.Is(err, jwt.ErrInvalidJWT()))
}
