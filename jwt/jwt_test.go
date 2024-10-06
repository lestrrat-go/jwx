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

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/internal/json"
	"github.com/lestrrat-go/jwx/v3/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	ourecdsa "github.com/lestrrat-go/jwx/v3/jwk/ecdsa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/lestrrat-go/jwx/v3/jwt/internal/types"
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

	alg := jwa.RS256()

	key, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err, `jwxtest.GenerateRsaKey should succeed`)
	t1 := jwt.New()
	signed, err := jwt.Sign(t1, jwt.WithKey(alg, key))
	require.NoError(t, err, `jwt.Sign should succeed`)
	t.Logf("%s", signed)

	t.Run("Parse (no signature verification)", func(t *testing.T) {
		t.Parallel()
		t2, err := jwt.ParseInsecure(signed)
		require.NoError(t, err, `jwt.Parse should succeed`)
		require.True(t, jwt.Equal(t1, t2), `t1 == t2`)
	})
	t.Run("ParseString (no signature verification)", func(t *testing.T) {
		t.Parallel()
		t2, err := jwt.ParseString(string(signed), jwt.WithVerify(false), jwt.WithValidate(false))
		require.NoError(t, err, `jwt.ParseString should succeed`)
		require.True(t, jwt.Equal(t1, t2), `t1 == t2`)
	})
	t.Run("ParseReader (no signature verification)", func(t *testing.T) {
		t.Parallel()
		t2, err := jwt.ParseReader(bytes.NewReader(signed), jwt.WithVerify(false), jwt.WithValidate(false))
		require.NoError(t, err, `jwt.ParseReader should succeed`)
		require.True(t, jwt.Equal(t1, t2), `t1 == t2`)
	})
	t.Run("Parse (correct signature key)", func(t *testing.T) {
		t.Parallel()
		t2, err := jwt.Parse(signed, jwt.WithKey(alg, &key.PublicKey))
		require.NoError(t, err, `jwt.Parse should succeed`)
		require.True(t, jwt.Equal(t1, t2), `t1 == t2`)
	})
	t.Run("parse (wrong signature algorithm)", func(t *testing.T) {
		t.Parallel()
		_, err := jwt.Parse(signed, jwt.WithKey(jwa.RS512(), &key.PublicKey))
		require.Error(t, err, `jwt.Parse should fail`)
	})
	t.Run("parse (wrong signature key)", func(t *testing.T) {
		t.Parallel()
		pubkey := key.PublicKey
		pubkey.E = 0 // bogus value
		_, err := jwt.Parse(signed, jwt.WithKey(alg, &pubkey))
		require.Error(t, err, `jwt.Parse should fail`)
	})
}

func TestJWTParseVerify(t *testing.T) {
	t.Parallel()

	keys := make([]interface{}, 0, 6)

	keys = append(keys, []byte("abracadabra"))

	rsaPrivKey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err, "RSA key generated")
	keys = append(keys, rsaPrivKey)

	for _, alg := range []jwa.EllipticCurveAlgorithm{jwa.P256(), jwa.P384(), jwa.P521()} {
		ecdsaPrivKey, err := jwxtest.GenerateEcdsaKey(alg)
		require.NoError(t, err, "jwxtest.GenerateEcdsaKey should succeed for %s", alg)
		keys = append(keys, ecdsaPrivKey)
	}

	ed25519PrivKey, err := jwxtest.GenerateEd25519Key()
	require.NoError(t, err, `jwxtest.GenerateEd25519Key should succeed`)
	keys = append(keys, ed25519PrivKey)

	for _, key := range keys {
		t.Run(fmt.Sprintf("Key=%T", key), func(t *testing.T) {
			t.Parallel()
			algs, err := jws.AlgorithmsForKey(key)
			require.NoError(t, err, `jwas.AlgorithmsForKey should succeed`)

			var dummyRawKey interface{}
			switch pk := key.(type) {
			case *rsa.PrivateKey:
				dummyRawKey, err = jwxtest.GenerateRsaKey()
				require.NoError(t, err, `jwxtest.GenerateRsaKey should succeed`)
			case *ecdsa.PrivateKey:
				alg, err := ourecdsa.AlgorithmFromCurve(pk.Curve)
				if err != nil {
					require.Fail(t, `unsupported elliptic.Curve: %w`, alg)
				}
				dummyRawKey, err = jwxtest.GenerateEcdsaKey(alg)
				require.NoError(t, err, `jwxtest.GenerateEcdsaKey should succeed`)
			case ed25519.PrivateKey:
				dummyRawKey, err = jwxtest.GenerateEd25519Key()
				require.NoError(t, err, `jwxtest.GenerateEd25519Key should succeed`)
			case []byte:
				dummyRawKey = jwxtest.GenerateSymmetricKey()
			default:
				require.Fail(t, fmt.Sprintf("Unhandled key type %T", key))
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
				for _, tc := range testcases {
					t.Run(fmt.Sprintf("Algorithm=%s, SetAlgorithm=%t, SetKid=%t, InferAlgorithm=%t, Expect Error=%t", alg, tc.SetAlgorithm, tc.SetKid, tc.InferAlgorithm, tc.Error), func(t *testing.T) {
						t.Parallel()

						const kid = "test-jwt-parse-verify-kid"
						const dummyKid = "test-jwt-parse-verify-dummy-kid"
						hdrs := jws.NewHeaders()
						hdrs.Set(jws.KeyIDKey, kid)

						t1 := jwt.New()
						signed, err := jwt.Sign(t1, jwt.WithKey(alg, key, jws.WithProtectedHeaders(hdrs)))
						require.NoError(t, err, "token.Sign should succeed")

						pubkey, err := jwk.PublicKeyOf(key)
						require.NoError(t, err, `jwk.PublicKeyOf should succeed`)

						if tc.SetAlgorithm {
							pubkey.Set(jwk.AlgorithmKey, alg)
						}

						dummyKey, err := jwk.PublicKeyOf(dummyRawKey)
						require.NoError(t, err, `jwk.PublicKeyOf should succeed`)

						if tc.SetKid {
							pubkey.Set(jwk.KeyIDKey, kid)
							dummyKey.Set(jwk.KeyIDKey, dummyKid)
						}

						// Permute on the location of the correct key, to check for possible
						// cases where we loop too little or too much.
						for i := range 6 {
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
									require.Error(t, err, `jwt.Parse should fail`)
									return
								}

								require.NoError(t, err, `jwt.Parse should succeed`)
								require.True(t, jwt.Equal(t1, t2), `t1 == t2`)
							})
						}
					})
				}
			}
		})
	}
	t.Run("Miscellaneous", func(t *testing.T) {
		key, err := jwxtest.GenerateRsaKey()
		require.NoError(t, err, "RSA key generated")
		var alg = jwa.RS256()
		const kid = "my-very-special-key"
		hdrs := jws.NewHeaders()
		hdrs.Set(jws.KeyIDKey, kid)
		t1 := jwt.New()
		signed, err := jwt.Sign(t1, jwt.WithKey(alg, key, jws.WithProtectedHeaders(hdrs)))
		require.NoError(t, err, "token.Sign should succeed")

		t.Run("Alg does not match", func(t *testing.T) {
			t.Parallel()
			pubkey, err := jwk.PublicKeyOf(key)
			require.NoError(t, err)

			require.NoError(t, pubkey.Set(jwk.AlgorithmKey, jwa.HS256()), `pubkey.Set should succeed`)
			require.NoError(t, pubkey.Set(jwk.KeyIDKey, kid), `pubkey.Set should succeed`)
			set := jwk.NewSet()
			set.AddKey(pubkey)

			_, err = jwt.Parse(signed, jwt.WithKeySet(set, jws.WithInferAlgorithmFromKey(true), jws.WithUseDefault(true)))
			require.Error(t, err, `jwt.Parse should fail`)
		})
		t.Run("UseDefault with a key set with 1 key", func(t *testing.T) {
			t.Parallel()
			pubkey, err := jwk.PublicKeyOf(key)
			require.NoError(t, err)

			pubkey.Set(jwk.AlgorithmKey, alg)
			pubkey.Set(jwk.KeyIDKey, kid)
			signedNoKid, err := jwt.Sign(t1, jwt.WithKey(alg, key))
			if err != nil {
				t.Fatal("Failed to sign JWT")
			}
			set := jwk.NewSet()
			set.AddKey(pubkey)
			t2, err := jwt.Parse(signedNoKid, jwt.WithKeySet(set, jws.WithUseDefault(true)))
			require.NoError(t, err, `jwt.Parse with key set should succeed`)
			require.True(t, jwt.Equal(t1, t2), `t1 == t2`)
		})
		t.Run("UseDefault with multiple keys should fail", func(t *testing.T) {
			t.Parallel()
			pubkey1, err := jwk.Import(&key.PublicKey)
			require.NoError(t, err)
			pubkey2, err := jwk.Import(&key.PublicKey)
			require.NoError(t, err)

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
			require.Error(t, err, `jwt.Parse should fail`)
		})
		// This is a test to check if we allow alg: none in the protected header section.
		// But in truth, since we delegate everything to jws.Verify anyways, it's really
		// a test to see if jws.Verify returns an error if alg: none is specified in the
		// header section. Move this test to jws if need be.
		t.Run("Check alg=none", func(t *testing.T) {
			t.Parallel()
			// Create a signed payload, but use alg=none
			_, payload, signature, err := jws.SplitCompact(signed)
			require.NoError(t, err, `jws.SplitCompact should succeed`)

			dummyHeader := jws.NewHeaders()
			for _, k := range hdrs.Keys() {
				var v interface{}
				require.NoError(t, hdrs.Get(k, &v), `hdrs.Get should succeed`)
				require.NoError(t, dummyHeader.Set(k, v), `dummyHeader.Set should succeed`)
			}
			dummyHeader.Set(jws.AlgorithmKey, jwa.NoSignature)

			dummyMarshaled, err := json.Marshal(dummyHeader)
			require.NoError(t, err, `json.Marshal should succeed`)
			dummyEncoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(dummyMarshaled)))
			base64.RawURLEncoding.Encode(dummyEncoded, dummyMarshaled)

			signedButNot := bytes.Join([][]byte{dummyEncoded, payload, signature}, []byte{'.'})

			pubkey, err := jwk.Import(&key.PublicKey)
			require.NoError(t, err)

			pubkey.Set(jwk.KeyIDKey, kid)

			set := jwk.NewSet()
			set.AddKey(pubkey)
			_, err = jwt.Parse(signedButNot, jwt.WithKeySet(set))
			// This should fail
			require.Error(t, err, `jwt.Parse with key set + alg=none should fail`)
		})
	})
}

func TestValidateClaims(t *testing.T) {
	t.Parallel()
	// GitHub issue #37: tokens are invalid in the second they are created (because Now() is not after IssuedAt())
	t.Run("Empty fields", func(t *testing.T) {
		t.Parallel()
		token := jwt.New()
		require.Error(t, jwt.Validate(token, jwt.WithIssuer("foo")), `token.Validate should fail`)
		require.Error(t, jwt.Validate(token, jwt.WithJwtID("foo")), `token.Validate should fail`)
		require.Error(t, jwt.Validate(token, jwt.WithSubject("foo")), `token.Validate should fail`)
	})
	t.Run("Reset Validator, No validator", func(t *testing.T) {
		t.Parallel()
		token := jwt.New()
		now := time.Now().UTC()
		token.Set(jwt.IssuedAtKey, now)

		err := jwt.Validate(token, jwt.WithResetValidators(true))
		require.Error(t, err, `token.Validate should fail`)
		require.Contains(t, err.Error(), "no validators specified", `error message should contain "no validators specified"`)
	})
	t.Run("Reset Validator, Check iss only", func(t *testing.T) {
		t.Parallel()
		token := jwt.New()
		iat := time.Now().UTC().Add(time.Hour * 24)
		token.Set(jwt.IssuedAtKey, iat)
		token.Set(jwt.IssuerKey, "github.com/lestrrat-go")

		err := jwt.Validate(token, jwt.WithResetValidators(true), jwt.WithIssuer("github.com/lestrrat-go"))
		require.NoError(t, err, `token.Validate should succeed`)
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

		require.NoError(t, jwt.Validate(token, args...), "token.Validate should validate tokens in the same second they are created")
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
		t.Run(tc.Title, func(t *testing.T) {
			t.Parallel()
			token := jwt.New()
			require.NoError(t, json.Unmarshal([]byte(tc.Source), &token), `json.Unmarshal should succeed`)
			require.Equal(t, tc.Expected(), token, `token should match expected value`)

			var buf bytes.Buffer
			require.NoError(t, json.NewEncoder(&buf).Encode(token), `json.Marshal should succeed`)
			require.Equal(t, tc.ExpectedJSON, strings.TrimSpace(buf.String()), `json should match`)
		})
	}
}

func TestGH52(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	t.Parallel()
	priv, err := jwxtest.GenerateEcdsaKey(jwa.P521())
	require.NoError(t, err)

	pub := &priv.PublicKey
	require.NoError(t, err)
	const iterations = 100
	var wg sync.WaitGroup
	wg.Add(iterations)
	for i := range iterations {
		// Do not use t.Run here as it will clutter up the outpuA
		go func(t *testing.T, priv *ecdsa.PrivateKey, i int) {
			defer wg.Done()
			tok := jwt.New()

			s, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), priv))
			require.NoError(t, err)
			_, err = jws.Verify(s, jws.WithKey(jwa.ES256(), pub))
			require.NoError(t, err, `test should pass (run %d)`, i)
		}(t, priv, i)
	}
	wg.Wait()
}

func TestUnmarshalJSON(t *testing.T) {
	t.Parallel()
	t.Run("Unmarshal audience with multiple values", func(t *testing.T) {
		t.Parallel()
		t1 := jwt.New()
		require.NoError(t, json.Unmarshal([]byte(`{"aud":["foo", "bar", "baz"]}`), &t1), `jwt.Parse should succeed`)

		var aud []string
		require.NoError(t, t1.Get(jwt.AudienceKey, &aud), `jwt.Get(jwt.AudienceKey) should succeed`)

		require.Equal(t, aud, []string{"foo", "bar", "baz"}, "audience should match. got %v", aud)
	})
}

func TestSignErrors(t *testing.T) {
	t.Parallel()
	priv, err := jwxtest.GenerateEcdsaKey(jwa.P521())
	require.NoError(t, err, `jwxtest.GenerateEcdsaKey should succeed`)

	tok := jwt.New()
	_, err = jwt.Sign(tok, jwt.WithKey(jwa.NewSignatureAlgorithm("BOGUS"), priv))
	require.Error(t, err)

	require.Contains(t, err.Error(), `unsupported signature algorithm "BOGUS"`)

	_, err = jwt.Sign(tok, jwt.WithKey(jwa.ES256(), nil))
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing private key")
}

func TestSignJWK(t *testing.T) {
	t.Parallel()
	priv, err := jwxtest.GenerateRsaKey()
	require.Nil(t, err)

	key, err := jwk.Import(priv)
	require.Nil(t, err)

	require.NoError(t, key.Set(jwk.KeyIDKey, "test"), `key.Set should succeed`)
	require.NoError(t, key.Set(jwk.AlgorithmKey, jwa.RS256()), `key.Set should succeed`)

	tok := jwt.New()
	signed, err := jwt.Sign(tok, jwt.WithKey(key.Algorithm(), key))
	require.Nil(t, err)

	header, err := jws.ParseString(string(signed))
	require.Nil(t, err)

	signatures := header.LookupSignature("test")
	require.Len(t, signatures, 1)
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
	require.NoError(t, err)

	t.Run(`"typ" header parameter should be set to JWT by default`, func(t *testing.T) {
		t.Parallel()
		t1 := jwt.New()
		signed, err := jwt.Sign(t1, jwt.WithKey(jwa.RS256(), key))
		require.NoError(t, err)
		got, err := getJWTHeaders(signed)
		require.NoError(t, err)
		v, ok := got.Type()
		require.True(t, ok, `"typ" header parameter should be set`)
		require.Equal(t, `JWT`, v, `"typ" header parameter should be set to JWT`)
	})

	t.Run(`"typ" header parameter should be customizable by WithHeaders`, func(t *testing.T) {
		t.Parallel()
		t1 := jwt.New()
		hdrs := jws.NewHeaders()
		hdrs.Set(`typ`, `custom-typ`)
		signed, err := jwt.Sign(t1, jwt.WithKey(jwa.RS256(), key, jws.WithProtectedHeaders(hdrs)))
		require.NoError(t, err)
		got, err := getJWTHeaders(signed)
		require.NoError(t, err)
		v, ok := got.Type()
		require.True(t, ok, `"typ" header parameter should be set`)
		require.Equal(t, `custom-typ`, v, `"typ" header parameter should be set to the custom value`)
	})
}

func TestReadFile(t *testing.T) {
	t.Parallel()

	f, err := os.CreateTemp("", "test-read-file-*.jwt")
	require.NoError(t, err, `os.CreateTemp should succeed`)
	defer f.Close()

	token := jwt.New()
	token.Set(jwt.IssuerKey, `lestrrat`)
	require.NoError(t, json.NewEncoder(f).Encode(token), `json.NewEncoder.Encode should succeed`)
	_, err = jwt.ReadFile(f.Name(), jwt.WithVerify(false), jwt.WithValidate(true), jwt.WithIssuer("lestrrat"))
	require.NoError(t, err, `jwt.ReadFile should succeed`)
	_, err = jwt.ReadFile(f.Name(), jwt.WithVerify(false), jwt.WithValidate(true), jwt.WithIssuer("lestrrrrrat"))
	require.Error(t, err, `jwt.ReadFile should fail`)
}

func TestCustomField(t *testing.T) {
	// XXX has global effect!!!
	const rfc3339Key = `x-test-rfc3339`
	const rfc1123Key = `x-test-rfc1123`
	jwt.RegisterCustomField(rfc3339Key, time.Time{})
	jwt.RegisterCustomField(rfc1123Key, jwt.CustomDecodeFunc(func(data []byte) (interface{}, error) {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return nil, err
		}
		return time.Parse(time.RFC1123, s)
	}))

	defer jwt.RegisterCustomField(rfc3339Key, nil)
	defer jwt.RegisterCustomField(rfc1123Key, nil)

	expected := time.Date(2015, 11, 4, 5, 12, 52, 0, time.UTC)

	rfc3339bytes, _ := expected.MarshalText() // RFC3339
	rfc1123bytes := expected.Format(time.RFC1123)
	var b strings.Builder
	b.WriteString(`{"iss": "github.com/lesstrrat-go/jwx", "`)
	b.WriteString(rfc3339Key)
	b.WriteString(`": "`)
	b.Write(rfc3339bytes)
	b.WriteString(`", "`)
	b.WriteString(rfc1123Key)
	b.WriteString(`": "`)
	b.WriteString(rfc1123bytes)
	b.WriteString(`"}`)
	src := b.String()

	t.Run("jwt.Parse", func(t *testing.T) {
		token, err := jwt.ParseInsecure([]byte(src))
		require.NoError(t, err, `jwt.Parse should succeed`)
		for _, key := range []string{rfc3339Key, rfc1123Key} {
			var v time.Time
			require.NoError(t, token.Get(key, &v), `token.Get(%q) should succeed`, key)
			require.Equal(t, expected, v, `values should match`)
		}
	})
	t.Run("json.Unmarshal", func(t *testing.T) {
		token := jwt.New()
		require.NoError(t, json.Unmarshal([]byte(src), token), `json.Unmarshal should succeed`)
		for _, key := range []string{rfc3339Key, rfc1123Key} {
			var v time.Time
			require.NoError(t, token.Get(key, &v), `token.Get(%q) should succeed`, key)
			require.Equal(t, expected, v, `values should match`)
		}
	})
}

func TestParseRequest(t *testing.T) {
	const u = "https://github.com/lestrrat-gow/jwx/jwt"
	const xauth = "X-Authorization"

	privkey, _ := jwxtest.GenerateEcdsaJwk()
	require.NoError(t, privkey.Set(jwk.AlgorithmKey, jwa.ES256()), `privkey.Set should succeed`)
	require.NoError(t, privkey.Set(jwk.KeyIDKey, `my-awesome-key`), `privkey.Set should succeed`)
	pubkey, err := jwk.PublicKeyOf(privkey)
	require.NoError(t, err, `jwk.PublicKeyOf should succeed`)
	require.NoError(t, pubkey.Set(jwk.AlgorithmKey, jwa.ES256()), `pubkey.Set should succeed`)

	tok := jwt.New()
	tok.Set(jwt.IssuerKey, u)
	tok.Set(jwt.IssuedAtKey, time.Now().Round(0))

	signed, _ := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), privkey))

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
					jwt.WithHeaderKey(xauth),
					jwt.WithFormKey("access_token"),
					jwt.WithFormKey("token"),
					jwt.WithCookieKey("cookie"),
					jwt.WithKey(jwa.ES256(), pubkey))
			},
			Error: true,
		},
		{
			Name: "Token not present (w/o options)",
			Request: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, u, nil)
			},
			Parse: func(req *http.Request) (jwt.Token, error) {
				return jwt.ParseRequest(req, jwt.WithKey(jwa.ES256(), pubkey))
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
				return jwt.ParseRequest(req, jwt.WithKey(jwa.ES256(), pubkey))
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
				require.NoError(t, set.AddKey(pubkey), `set.AddKey should succeed`)
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
				return jwt.ParseRequest(req, jwt.WithHeaderKey(xauth), jwt.WithKey(jwa.ES256(), pubkey))
			},
			Error: true,
		},
		{
			Name: fmt.Sprintf("Token in %s header (w/ option)", xauth),
			Request: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, u, nil)
				req.Header.Add(xauth, string(signed))
				return req
			},
			Parse: func(req *http.Request) (jwt.Token, error) {
				return jwt.ParseRequest(req, jwt.WithHeaderKey(xauth), jwt.WithKey(jwa.ES256(), pubkey))
			},
		},
		{
			Name: fmt.Sprintf("Invalid token in %s header", xauth),
			Request: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, u, nil)
				req.Header.Add(xauth, string(signed)+"foobarbaz")
				return req
			},
			Parse: func(req *http.Request) (jwt.Token, error) {
				return jwt.ParseRequest(req, jwt.WithHeaderKey(xauth), jwt.WithKey(jwa.ES256(), pubkey))
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
				return jwt.ParseRequest(req, jwt.WithFormKey("access_token"), jwt.WithKey(jwa.ES256(), pubkey))
			},
		},
		{
			Name: "Token in cookie (w/ option)",
			Request: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, u, nil)
				req.AddCookie(&http.Cookie{Name: "cookie", Value: string(signed)})
				return req
			},
			Parse: func(req *http.Request) (jwt.Token, error) {
				return jwt.ParseRequest(req, jwt.WithCookieKey("cookie"), jwt.WithKey(jwa.ES256(), pubkey))
			},
		},
		{
			Name: "Invalid token in cookie",
			Request: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, u, nil)
				req.AddCookie(&http.Cookie{Name: "cookie", Value: string(signed) + "foobarbaz"})
				return req
			},
			Parse: func(req *http.Request) (jwt.Token, error) {
				return jwt.ParseRequest(req, jwt.WithCookieKey("cookie"), jwt.WithKey(jwa.ES256(), pubkey))
			},
			Error: true,
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
				return jwt.ParseRequest(req, jwt.WithKey(jwa.ES256(), pubkey))
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
				return jwt.ParseRequest(req, jwt.WithKey(jwa.ES256(), pubkey), jwt.WithFormKey("access_token"))
			},
			Error: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.Name, func(t *testing.T) {
			got, err := tc.Parse(tc.Request())
			if tc.Error {
				t.Logf("%s", err)
				require.Error(t, err, `tc.Parse should fail`)
				return
			}

			require.NoError(t, err, `tc.Parse should succeed`)
			require.True(t, jwt.Equal(tok, got), `tokens should match`)
		})
	}

	// One extra test. Make sure we can extract the cookie object that we used
	// when parsing from cookies
	t.Run("jwt.WithCookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, u, nil)
		req.AddCookie(&http.Cookie{Name: "cookie", Value: string(signed)})
		var dst *http.Cookie
		_, err := jwt.ParseRequest(req, jwt.WithCookieKey("cookie"), jwt.WithCookie(&dst), jwt.WithKey(jwa.ES256(), pubkey))
		require.NoError(t, err, `jwt.ParseRequest should succeed`)
		require.NotNil(t, dst, `cookie should be extracted`)
	})
}

func TestGHIssue368(t *testing.T) {
	// DO NOT RUN THIS IN PARALLEL
	t.Run("Per-object control of flatten audience", func(t *testing.T) {
		for _, globalFlatten := range []bool{true, false} {
			for _, perObjectFlatten := range []bool{true, false} {
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
					require.NoError(t, err, `json.MarshalIndent should succeed`)
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

					require.Equal(t, expected, string(buf), `output should match`)
				})
			}
		}
	})

	for _, flatten := range []bool{true, false} {
		t.Run(fmt.Sprintf("Test serialization (WithFlattenAudience(%t))", flatten), func(t *testing.T) {
			jwt.Settings(jwt.WithFlattenAudience(flatten))

			t.Run("Single Key", func(t *testing.T) {
				tok := jwt.New()
				_ = tok.Set(jwt.AudienceKey, "hello")

				buf, err := json.MarshalIndent(tok, "", "  ")
				require.NoError(t, err, `json.MarshalIndent should succeed`)

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

				require.Equal(t, expected, string(buf), `output should match`)
			})
			t.Run("Multiple Keys", func(t *testing.T) {
				tok, err := jwt.NewBuilder().
					Audience([]string{"hello", "world"}).
					Build()
				require.NoError(t, err, `jwt.Builder should succeed`)

				buf, err := json.MarshalIndent(tok, "", "  ")
				require.NoError(t, err, `json.MarshalIndent should succeed`)

				const expected = `{
  "aud": [
    "hello",
    "world"
  ]
}`

				require.Equal(t, expected, string(buf), `output should match`)
			})
		})
	}
}

func TestGH375(t *testing.T) {
	key, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err, `jwxtest.GenerateRsaJwk should succeed`)
	key.Set(jwk.KeyIDKey, `test`)

	token, err := jwt.NewBuilder().
		Issuer(`foobar`).
		Build()
	require.NoError(t, err, `jwt.Builder should succeed`)

	signAlg := jwa.RS512()
	signed, err := jwt.Sign(token, jwt.WithKey(signAlg, key))
	require.NoError(t, err, `jwt.Sign should succeed`)

	verifyKey, err := jwk.PublicKeyOf(key)
	require.NoError(t, err, `jwk.PublicKeyOf should succeed`)

	verifyKey.Set(jwk.KeyIDKey, `test`)
	verifyKey.Set(jwk.AlgorithmKey, jwa.RS256) // != jwa.RS512

	ks := jwk.NewSet()
	ks.AddKey(verifyKey)

	_, err = jwt.Parse(signed, jwt.WithKeySet(ks))
	require.Error(t, err, `jwt.Parse should fail`)
}

type Claim struct {
	Foo string
	Bar int64
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
	require.NoError(t, err, `jwxtest.GenerateRsaKey should succeed`)

	var signed []byte
	{
		token := jwt.New()
		require.NoError(t, token.Set("typed-claim", expected), `expected.Set should succeed`)
		v, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), key))
		require.NoError(t, err, `jwt.Sign should succeed`)
		signed = v
	}

	for _, tc := range testcases {
		t.Run(tc.Name, func(t *testing.T) {
			options := append(tc.Options, jwt.WithVerify(false))
			got, err := jwt.Parse(signed, options...)
			require.NoError(t, err, `jwt.Parse should succeed`)

			var v interface{}
			require.NoError(t, got.Get("typed-claim", &v), `got.Get() should succeed`)

			claim, err := tc.PostProcess(t, v)
			require.NoError(t, err, `tc.PostProcess should succeed`)
			require.Equal(t, claim, expected, `claim should match expected value`)
		})
	}
}

func TestGH393(t *testing.T) {
	t.Run("Non-existent required claims", func(t *testing.T) {
		tok := jwt.New()
		require.Error(t, jwt.Validate(tok, jwt.WithRequiredClaim(jwt.IssuedAtKey)), `jwt.Validate should fail`)
	})
	t.Run("exp - iat < WithMaxDelta(10 secs)", func(t *testing.T) {
		now := time.Now()
		tok, err := jwt.NewBuilder().
			IssuedAt(now).
			Expiration(now.Add(5 * time.Second)).
			Build()
		require.NoError(t, err, `jwt.Builder should succeed`)
		require.Error(t, jwt.Validate(tok, jwt.WithMaxDelta(2*time.Second, jwt.ExpirationKey, jwt.IssuedAtKey)), `jwt.Validate should fail`)
		require.NoError(t, jwt.Validate(tok, jwt.WithMaxDelta(10*time.Second, jwt.ExpirationKey, jwt.IssuedAtKey)), `jwt.Validate should succeed`)
	})
	t.Run("iat - exp (5 secs) < WithMinDelta(10 secs)", func(t *testing.T) {
		now := time.Now()
		tok, err := jwt.NewBuilder().
			IssuedAt(now).
			Expiration(now.Add(5 * time.Second)).
			Build()
		require.NoError(t, err, `jwt.Builder should succeed`)
		require.Error(t, jwt.Validate(tok, jwt.WithMinDelta(10*time.Second, jwt.ExpirationKey, jwt.IssuedAtKey)), `jwt.Validate should fail`)
	})
	t.Run("iat - exp (5 secs) > WithMinDelta(10 secs)", func(t *testing.T) {
		now := time.Now()
		tok, err := jwt.NewBuilder().
			IssuedAt(now).
			Expiration(now.Add(5 * time.Second)).
			Build()
		require.NoError(t, err, `jwt.Builder should succeed`)
		require.NoError(t, jwt.Validate(tok, jwt.WithMinDelta(10*time.Second, jwt.ExpirationKey, jwt.IssuedAtKey), jwt.WithAcceptableSkew(5*time.Second)), `jwt.Validate should succeed`)
	})
	t.Run("now - iat < WithMaxDelta(10 secs)", func(t *testing.T) {
		now := time.Now()
		tok, err := jwt.NewBuilder().
			IssuedAt(now).
			Build()
		require.NoError(t, err, `jwt.Builder should succeed`)
		require.NoError(t, jwt.Validate(tok, jwt.WithMaxDelta(10*time.Second, "", jwt.IssuedAtKey), jwt.WithClock(jwt.ClockFunc(func() time.Time { return now.Add(5 * time.Second) }))), `jwt.Validate should succeed`)
	})
	t.Run("invalid claim name (c1)", func(t *testing.T) {
		now := time.Now()
		tok, err := jwt.NewBuilder().
			Claim("foo", now).
			Expiration(now.Add(5 * time.Second)).
			Build()
		require.NoError(t, err, `jwt.Builder should succeed`)
		require.Error(t, jwt.Validate(tok, jwt.WithMinDelta(10*time.Second, jwt.ExpirationKey, "foo"), jwt.WithAcceptableSkew(5*time.Second)), `jwt.Validate should fail`)
	})
	t.Run("invalid claim name (c2)", func(t *testing.T) {
		now := time.Now()
		tok, err := jwt.NewBuilder().
			Claim("foo", now.Add(5*time.Second)).
			IssuedAt(now).
			Build()
		require.NoError(t, err, `jwt.Builder should succeed`)
		require.Error(t, jwt.Validate(tok, jwt.WithMinDelta(10*time.Second, "foo", jwt.IssuedAtKey), jwt.WithAcceptableSkew(5*time.Second)), `jwt.Validate should fail`)
	})

	// Following tests deviate a little from the original issue, but
	// since they were added for the same issue, we just bundle the
	// tests together
	t.Run(`WithRequiredClaim fails for non-existent claim`, func(t *testing.T) {
		tok := jwt.New()
		require.Error(t, jwt.Validate(tok, jwt.WithRequiredClaim("foo")), `jwt.Validate should fail`)
	})
	t.Run(`WithRequiredClaim succeeds for existing claim`, func(t *testing.T) {
		tok, err := jwt.NewBuilder().
			Claim(`foo`, 1).
			Build()
		require.NoError(t, err, `jwt.Builder should succeed`)
		require.NoError(t, jwt.Validate(tok, jwt.WithRequiredClaim("foo")), `jwt.Validate should fail`)
	})
}

func TestGH430(t *testing.T) {
	t1 := jwt.New()
	err := t1.Set("payload", map[string]interface{}{
		"name": "someone",
	})
	require.NoError(t, err, `t1.Set should succeed`)

	key := []byte("secret")
	signed, err := jwt.Sign(t1, jwt.WithKey(jwa.HS256(), key))
	require.NoError(t, err, `jwt.Sign should succeed`)

	_, err = jwt.Parse(signed, jwt.WithKey(jwa.HS256(), key))
	require.NoError(t, err, `jwt.Parse should succeed`)
}

func TestGH706(t *testing.T) {
	err := jwt.Validate(jwt.New(), jwt.WithRequiredClaim("foo"))
	require.True(t, jwt.IsValidationError(err), `error should be a validation error`)
	require.ErrorIs(t, err, jwt.ErrRequiredClaim(), `jwt.Validate should fail`)
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
				jwt.WithKey(jwa.RS256(), &key.PublicKey),
			)
			t.Logf("%s", err)
			require.Error(t, err, `jwt.Parse should fail`)
		}
	}
}

func TestVerifyAuto(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	key, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err, `jwxtest.GenerateRsaJwk should succeed`)

	key.Set(jwk.KeyIDKey, `my-awesome-key`)

	pubkey, err := jwk.PublicKeyOf(key)
	require.NoError(t, err, `jwk.PublicKeyOf should succeed`)
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
		Claim(jwt.IssuerKey, `https://github.com/lestrrat-go/jwx/v3`).
		Claim(jwt.SubjectKey, `jku-test`).
		Build()

	require.NoError(t, err, `jwt.NewBuilder.Build() should succeed`)

	hdrs := jws.NewHeaders()
	hdrs.Set(jws.JWKSetURLKey, srv.URL)

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), key, jws.WithProtectedHeaders(hdrs)))
	require.NoError(t, err, `jwt.Sign() should succeed`)

	wl := jwk.NewMapWhitelist().
		Add(srv.URL)

	parsed, err := jwt.Parse(signed, jwt.WithVerifyAuto(nil, jwk.WithFetchWhitelist(wl), jwk.WithHTTPClient(srv.Client())))
	require.NoError(t, err, `jwt.Parse should succeed`)
	require.True(t, jwt.Equal(tok, parsed), `tokens should be equal`)

	_, err = jwt.Parse(signed, jwt.WithVerifyAuto(nil))
	require.Error(t, err, `jwt.Parse should fail`)
	wl = jwk.NewMapWhitelist().
		Add(`https://github.com/lestrrat-go/jwx/v3`)
	_, err = jwt.Parse(signed, jwt.WithVerifyAuto(nil, jwk.WithFetchWhitelist(wl)))
	require.Error(t, err, `jwt.Parse should fail`)

	// now with Cache
	c, err := jwk.NewCache(ctx, httprc.NewClient())
	require.NoError(t, err, `jwk.NewCache should succeed`)
	parsed, err = jwt.Parse(signed,
		jwt.WithVerifyAuto(
			jwk.FetchFunc(func(ctx context.Context, u string, options ...jwk.FetchOption) (jwk.Set, error) {
				var registeropts []jwk.RegisterOption
				// jwk.FetchOption is also an CacheOption, but the container
				// doesn't match the signature... so... we need to convert them...
				for _, option := range options {
					registeropts = append(registeropts, option)
				}
				c.Register(ctx, u, registeropts...)
				return c.Lookup(ctx, u)
			}),
			jwk.WithHTTPClient(srv.Client()),
			jwk.WithFetchWhitelist(jwk.InsecureWhitelist{}),
		),
	)
	require.NoError(t, err, `jwt.Parse should succeed`)
	require.True(t, jwt.Equal(tok, parsed), `tokens should be equal`)
}

func TestSerializer(t *testing.T) {
	t.Run(`Invalid sign suboption`, func(t *testing.T) {
		_, err := jwt.NewSerializer().
			Sign(jwt.WithKey(jwa.HS256(), []byte("abracadabra"), jwe.WithCompress(jwa.Deflate()))).
			Serialize(jwt.New())
		require.Error(t, err, `Serialize() should fail`)
	})
	t.Run(`Invalid SignatureAglrotihm`, func(t *testing.T) {
		_, err := jwt.NewSerializer().
			Encrypt(jwt.WithKey(jwa.A256KW(), []byte("abracadabra"))).
			Serialize(jwt.New())
		require.Error(t, err, `Serialize() should succeedl`)
	})
	t.Run(`Invalid encrypt suboption`, func(t *testing.T) {
		_, err := jwt.NewSerializer().
			Encrypt(jwt.WithKey(jwa.A256KW(), []byte("abracadabra"), jws.WithPretty(true))).
			Serialize(jwt.New())
		require.Error(t, err, `Serialize() should fail`)
	})
	t.Run(`Invalid KeyEncryptionAglrotihm`, func(t *testing.T) {
		_, err := jwt.NewSerializer().
			Encrypt(jwt.WithKey(jwa.HS256(), []byte("abracadabra"))).
			Serialize(jwt.New())
		require.Error(t, err, `Serialize() should succeedl`)
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

func TestGH888(t *testing.T) {
	// Use of "none" is insecure, and we just don't allow it by default.
	// In order to allow none, we must tell jwx that we actually want it.
	token, err := jwt.NewBuilder().
		Subject("foo").
		Issuer("bar").
		Build()

	require.NoError(t, err, `jwt.Builder should succeed`)

	// 1) "none" must be triggered by its own option. Can't use jwt.WithKey(jwa.NoSignature, ...)
	t.Run("jwt.Sign(token, jwt.WithKey(jwa.NoSignature)) should fail", func(t *testing.T) {
		_, err := jwt.Sign(token, jwt.WithKey(jwa.NoSignature(), nil))
		require.Error(t, err, `jwt.Sign with jwt.WithKey should fail`)
	})
	t.Run("jwt.Sign(token, jwt.WithInsecureNoSignature())", func(t *testing.T) {
		signed, err := jwt.Sign(token, jwt.WithInsecureNoSignature())
		require.NoError(t, err, `jwt.Sign should succeed`)

		require.Equal(t, `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJiYXIiLCJzdWIiOiJmb28ifQ.`, string(signed))

		_, err = jwt.Parse(signed)
		require.Error(t, err, `jwt.Parse with alg=none should fail`)
	})
}

func TestGH951(t *testing.T) {
	signKey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err, `jwxtest.GenerateRsaKey should succeed`)

	sharedKey := []byte{
		25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133, 74, 82,
	}

	token, err := jwt.NewBuilder().
		Subject(`test-951`).
		Issuer(`jwt.Test951`).
		Build()
	require.NoError(t, err, `jwt.NewBuilder should succeed`)

	// this whole workflow actually works even if the bug in #951 is present.
	// so we shall compare the results with and without the encryption
	// options to see if there is a difference in the length of the
	// cipher text, which is the second from last component in the message
	serialized, err := jwt.NewSerializer().
		Sign(jwt.WithKey(jwa.RS256(), signKey)).
		Encrypt(
			jwt.WithKey(jwa.A128KW(), sharedKey),
			jwt.WithEncryptOption(jwe.WithContentEncryption(jwa.A128GCM())),
			jwt.WithEncryptOption(jwe.WithCompress(jwa.Deflate())),
		).
		Serialize(token)
	require.NoError(t, err, `jwt.NewSerializer()....Serizlie() should succeed`)

	serialized2, err := jwt.NewSerializer().
		Sign(jwt.WithKey(jwa.RS256(), signKey)).
		Encrypt(
			jwt.WithKey(jwa.A128KW(), sharedKey),
		).
		Serialize(token)
	require.NoError(t, err, `jwt.NewSerializer()....Serizlie() should succeed`)

	require.NotEqual(t,
		len(bytes.Split(serialized, []byte{'.'})[3]),
		len(bytes.Split(serialized2, []byte{'.'})[3]),
	)

	decrypted, err := jwe.Decrypt(serialized, jwe.WithKey(jwa.A128KW(), sharedKey))
	require.NoError(t, err, `jwe.Decrypt should succeed`)

	verified, err := jwt.Parse(decrypted, jwt.WithKey(jwa.RS256(), signKey.PublicKey))
	require.NoError(t, err, `jwt.Parse should succeed`)

	require.True(t, jwt.Equal(verified, token), `tokens should be equal`)
}

func TestGH1007(t *testing.T) {
	key, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err, `jwxtest.GenerateRsaJwk should succeed`)

	tok, err := jwt.NewBuilder().
		Claim(`claim1`, `value1`).
		Claim(`claim2`, `value2`).
		Issuer(`github.com/lestrrat-go/jwx`).
		Audience([]string{`users`}).
		Build()
	require.NoError(t, err, `jwt.NewBuilder should succeed`)

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), key))
	require.NoError(t, err, `jwt.Sign should succeed`)

	// This was the intended usage (no WithKey). This worked from the beginning
	_, err = jwt.ParseInsecure(signed)
	require.NoError(t, err, `jwt.ParseInsecure should succeed`)

	// This is the problematic behavior reporded in #1007.
	// The fact that we're specifying a wrong key caused Parse() to check for
	// verification and yet fail :/
	wrongPubKey, err := jwxtest.GenerateRsaPublicJwk()
	require.NoError(t, err, `jwxtest.GenerateRsaPublicJwk should succeed`)
	require.NoError(t, err, `jwk.PublicKeyOf should succeed`)

	_, err = jwt.ParseInsecure(signed, jwt.WithKey(jwa.RS256(), wrongPubKey))
	require.NoError(t, err, `jwt.ParseInsecure with jwt.WithKey() should succeed`)
}

func TestParseJSON(t *testing.T) {
	// NOTE: Unlike in v2, there is no setting for CompactOnly
	privKey, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err, `jwxtest.GenerateRsaJwk should succeed`)

	signedJSON, err := jws.Sign([]byte(`{}`), jws.WithKey(jwa.RS256(), privKey), jws.WithValidateKey(true), jws.WithJSON())
	require.NoError(t, err, `jws.Sign should succeed`)

	// jws.Verify should succeed
	_, err = jws.Verify(signedJSON, jws.WithKey(jwa.RS256(), privKey))
	require.NoError(t, err, `jws.Verify should succeed`)

	// jwt.Parse should fail
	_, err = jwt.Parse(signedJSON, jwt.WithKey(jwa.RS256(), privKey))
	require.Error(t, err, `jwt.Parse should fail`)
}

func TestGH1175(t *testing.T) {
	token, err := jwt.NewBuilder().
		Expiration(time.Now().Add(-1 * time.Hour)).
		Build()
	require.NoError(t, err, `jwt.NewBuilder should succeed`)
	secret := []byte("secret")
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.HS256(), secret))
	require.NoError(t, err, `jwt.Sign should succeed`)

	req := httptest.NewRequest(http.MethodGet, `http://example.com`, nil)
	req.Header.Set("Authorization", "Bearer "+string(signed))

	_, err = jwt.ParseRequest(req, jwt.WithKey(jwa.HS256(), secret))
	require.Error(t, err, `jwt.ParseRequest should fail`)
	require.ErrorIs(t, err, jwt.ErrTokenExpired(), `jwt.ParseRequest should fail with jwt.ErrTokenExpired`)
}
