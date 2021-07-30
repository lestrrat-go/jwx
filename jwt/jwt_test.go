package jwt_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/internal/json"
	"github.com/lestrrat-go/jwx/internal/jwxtest"
	"github.com/lestrrat-go/jwx/jwe"
	"github.com/pkg/errors"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/stretchr/testify/assert"
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
	signed, err := jwt.Sign(t1, alg, key)
	if !assert.NoError(t, err, `jwt.Sign should succeed`) {
		return
	}

	t.Logf("%s", signed)

	t.Run("Parse (no signature verification)", func(t *testing.T) {
		t.Parallel()
		t2, err := jwt.Parse(signed)
		if !assert.NoError(t, err, `jwt.Parse should succeed`) {
			return
		}
		if !assert.True(t, jwt.Equal(t1, t2), `t1 == t2`) {
			return
		}
	})
	t.Run("ParseString (no signature verification)", func(t *testing.T) {
		t.Parallel()
		t2, err := jwt.ParseString(string(signed))
		if !assert.NoError(t, err, `jwt.ParseString should succeed`) {
			return
		}
		if !assert.True(t, jwt.Equal(t1, t2), `t1 == t2`) {
			return
		}
	})
	t.Run("ParseReader (no signature verification)", func(t *testing.T) {
		t.Parallel()
		t2, err := jwt.ParseReader(bytes.NewReader(signed))
		if !assert.NoError(t, err, `jwt.ParseBytes should succeed`) {
			return
		}
		if !assert.True(t, jwt.Equal(t1, t2), `t1 == t2`) {
			return
		}
	})
	t.Run("Parse (correct signature key)", func(t *testing.T) {
		t.Parallel()
		t2, err := jwt.Parse(signed, jwt.WithVerify(alg, &key.PublicKey))
		if !assert.NoError(t, err, `jwt.Parse should succeed`) {
			return
		}
		if !assert.True(t, jwt.Equal(t1, t2), `t1 == t2`) {
			return
		}
	})
	t.Run("parse (wrong signature algorithm)", func(t *testing.T) {
		t.Parallel()
		_, err := jwt.Parse(signed, jwt.WithVerify(jwa.RS512, &key.PublicKey))
		if !assert.Error(t, err, `jwt.Parse should fail`) {
			return
		}
	})
	t.Run("parse (wrong signature key)", func(t *testing.T) {
		t.Parallel()
		pubkey := key.PublicKey
		pubkey.E = 0 // bogus value
		_, err := jwt.Parse(signed, jwt.WithVerify(alg, &pubkey))
		if !assert.Error(t, err, `jwt.Parse should fail`) {
			return
		}
	})
}

func TestJWTParseVerify(t *testing.T) {
	t.Parallel()
	alg := jwa.RS256
	key, err := jwxtest.GenerateRsaKey()
	if !assert.NoError(t, err, "RSA key generated") {
		return
	}

	kid := "test-jwt-parse-verify-kid"
	hdrs := jws.NewHeaders()
	hdrs.Set(jws.KeyIDKey, kid)

	t1 := jwt.New()

	signed, err := jwt.Sign(t1, alg, key, jwt.WithHeaders(hdrs))
	if !assert.NoError(t, err, "token.Sign should succeed") {
		return
	}

	t.Run("Parse (w/jwk.Set)", func(t *testing.T) {
		t.Parallel()
		t.Run("Automatically pick a key from set", func(t *testing.T) {
			t.Parallel()
			pubkey := jwk.NewRSAPublicKey()
			if !assert.NoError(t, pubkey.FromRaw(&key.PublicKey)) {
				return
			}

			pubkey.Set(jwk.AlgorithmKey, alg)
			pubkey.Set(jwk.KeyIDKey, kid)

			set := jwk.NewSet()
			set.Add(pubkey)
			t2, err := jwt.Parse(signed, jwt.WithKeySet(set))
			if !assert.NoError(t, err, `jwt.Parse with key set should succeed`) {
				return
			}

			if !assert.True(t, jwt.Equal(t1, t2), `t1 == t2`) {
				return
			}
		})
		t.Run("No kid should fail", func(t *testing.T) {
			t.Parallel()
			pubkey := jwk.NewRSAPublicKey()
			if !assert.NoError(t, pubkey.FromRaw(&key.PublicKey)) {
				return
			}

			pubkey.Set(jwk.KeyIDKey, kid)
			signedNoKid, err := jwt.Sign(t1, alg, key)
			if err != nil {
				t.Fatal("Failed to sign JWT")
			}

			set := jwk.NewSet()
			set.Add(pubkey)
			_, err = jwt.Parse(signedNoKid, jwt.WithKeySet(set))
			if !assert.Error(t, err, `jwt.Parse should fail`) {
				return
			}
		})
		t.Run("Pick default key from set of 1", func(t *testing.T) {
			t.Parallel()
			pubkey := jwk.NewRSAPublicKey()
			if !assert.NoError(t, pubkey.FromRaw(&key.PublicKey)) {
				return
			}

			pubkey.Set(jwk.AlgorithmKey, alg)
			pubkey.Set(jwk.KeyIDKey, kid)
			signedNoKid, err := jwt.Sign(t1, alg, key)
			if err != nil {
				t.Fatal("Failed to sign JWT")
			}
			set := jwk.NewSet()
			set.Add(pubkey)
			t2, err := jwt.Parse(signedNoKid, jwt.WithKeySet(set), jwt.UseDefaultKey(true))
			if !assert.NoError(t, err, `jwt.Parse with key set should succeed`) {
				return
			}
			if !assert.True(t, jwt.Equal(t1, t2), `t1 == t2`) {
				return
			}
		})
		t.Run("UseDefault with multiple keys should fail", func(t *testing.T) {
			t.Parallel()
			pubkey1 := jwk.NewRSAPublicKey()
			if !assert.NoError(t, pubkey1.FromRaw(&key.PublicKey)) {
				return
			}
			pubkey2 := jwk.NewRSAPublicKey()
			if !assert.NoError(t, pubkey2.FromRaw(&key.PublicKey)) {
				return
			}

			pubkey1.Set(jwk.KeyIDKey, kid)
			pubkey2.Set(jwk.KeyIDKey, "test-jwt-parse-verify-kid-2")
			signedNoKid, err := jwt.Sign(t1, alg, key)
			if err != nil {
				t.Fatal("Failed to sign JWT")
			}
			set := jwk.NewSet()
			set.Add(pubkey1)
			set.Add(pubkey2)
			_, err = jwt.Parse(signedNoKid, jwt.WithKeySet(set), jwt.UseDefaultKey(true))
			if !assert.Error(t, err, `jwt.Parse should fail`) {
				return
			}
		})
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

		pubkey := jwk.NewRSAPublicKey()
		if !assert.NoError(t, pubkey.FromRaw(&key.PublicKey)) {
			return
		}

		pubkey.Set(jwk.KeyIDKey, kid)

		set := jwk.NewSet()
		set.Add(pubkey)
		_, err = jwt.Parse(signedButNot, jwt.WithKeySet(set))
		// This should fail
		if !assert.Error(t, err, `jwt.Parse with key set + alg=none should fail`) {
			return
		}
	})
}

func TestValidateClaims(t *testing.T) {
	t.Parallel()
	// GitHub issue #37: tokens are invalid in the second they are created (because Now() is not after IssuedAt())
	t.Run("Empty fields", func(t *testing.T) {
		token := jwt.New()

		if !assert.Error(t, jwt.Validate(token, jwt.WithIssuer("foo")), `token.Validate shold fail`) {
			return
		}
		if !assert.Error(t, jwt.Validate(token, jwt.WithJwtID("foo")), `token.Validate shold fail`) {
			return
		}
		if !assert.Error(t, jwt.Validate(token, jwt.WithSubject("foo")), `token.Validate shold fail`) {
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

			s, err := jwt.Sign(tok, jwa.ES256, priv)
			if !assert.NoError(t, err) {
				return
			}

			if _, err = jws.Verify(s, jwa.ES256, pub); !assert.NoError(t, err, `test should pass (run %d)`, i) {
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
	_, err = jwt.Sign(tok, jwa.SignatureAlgorithm("BOGUS"), priv)
	if !assert.Error(t, err) {
		return
	}

	if !assert.Contains(t, err.Error(), `unsupported signature algorithm "BOGUS"`) {
		return
	}

	_, err = jwt.Sign(tok, jwa.ES256, nil)
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

	key := jwk.NewRSAPrivateKey()
	err = key.FromRaw(priv)
	assert.Nil(t, err)

	key.Set(jwk.KeyIDKey, "test")
	key.Set(jwk.AlgorithmKey, jwa.RS256)

	tok := jwt.New()
	signed, err := jwt.Sign(tok, jwa.SignatureAlgorithm(key.Algorithm()), key)
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
		signed, err := jwt.Sign(t1, jwa.RS256, key)
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
		signed, err := jwt.Sign(t1, jwa.RS256, key, jwt.WithHeaders(hdrs))
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

	f, err := ioutil.TempFile("", "test-read-file-*.jwt")
	if !assert.NoError(t, err, `ioutil.TempFile should succeed`) {
		return
	}
	defer f.Close()

	token := jwt.New()
	token.Set(jwt.IssuerKey, `lestrrat`)
	if !assert.NoError(t, json.NewEncoder(f).Encode(token), `json.NewEncoder.Encode should succeed`) {
		return
	}

	if _, err := jwt.ReadFile(f.Name(), jwt.WithValidate(true), jwt.WithIssuer("lestrrat")); !assert.NoError(t, err, `jwt.ReadFile should succeed`) {
		return
	}
	if _, err := jwt.ReadFile(f.Name(), jwt.WithValidate(true), jwt.WithIssuer("lestrrrrrat")); !assert.Error(t, err, `jwt.ReadFile should fail`) {
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
		token, err := jwt.Parse([]byte(src))
		if !assert.NoError(t, err, `jwt.Parse should succeed`) {
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
	pubkey, _ := jwk.PublicKeyOf(privkey)

	tok := jwt.New()
	tok.Set(jwt.IssuerKey, u)
	tok.Set(jwt.IssuedAtKey, time.Now().Round(0))

	signed, _ := jwt.Sign(tok, jwa.ES256, privkey)

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
					jwt.WithVerify(jwa.ES256, pubkey))
			},
			Error: true,
		},
		{
			Name: "Token not present (w/o options)",
			Request: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, u, nil)
			},
			Parse: func(req *http.Request) (jwt.Token, error) {
				return jwt.ParseRequest(req, jwt.WithVerify(jwa.ES256, pubkey))
			},
			Error: true,
		},
		{
			Name: "Token in Authorization header (w/o options)",
			Request: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, u, nil)
				req.Header.Add("Authorization", "Bearer "+string(signed))
				return req
			},
			Parse: func(req *http.Request) (jwt.Token, error) {
				return jwt.ParseRequest(req, jwt.WithVerify(jwa.ES256, pubkey))
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
				return jwt.ParseRequest(req, jwt.WithHeaderKey("x-authorization"), jwt.WithVerify(jwa.ES256, pubkey))
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
				return jwt.ParseRequest(req, jwt.WithHeaderKey("x-authorization"), jwt.WithVerify(jwa.ES256, pubkey))
			},
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
				return jwt.ParseRequest(req, jwt.WithFormKey("access_token"), jwt.WithVerify(jwa.ES256, pubkey))
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
				return jwt.ParseRequest(req, jwt.WithVerify(jwa.ES256, pubkey))
			},
			Error: true,
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			got, err := tc.Parse(tc.Request())
			if tc.Error {
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
				tok := jwt.New()
				_ = tok.Set(jwt.AudienceKey, []string{"hello", "world"})

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

	token := jwt.New()
	token.Set(jwt.IssuerKey, `foobar`)

	signAlg := jwa.RS512
	signed, err := jwt.Sign(token, signAlg, key)
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
	ks.Add(verifyKey)

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
					return nil, errors.Errorf(`claim value should be of type "Claim", but got %T`, claim)
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
					return nil, errors.Errorf(`claim value should be of type "json.RawMessage", but got %T`, claim)
				}

				var c Claim
				if err := json.Unmarshal(v, &c); err != nil {
					return nil, errors.Wrap(err, `json.Unmarshal failed`)
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
		v, err := jwt.Sign(token, jwa.RS256, key)
		if !assert.NoError(t, err, `jws.Sign should succeed`) {
			return
		}
		signed = v
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			got, err := jwt.Parse(signed, tc.Options...)
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
		tok := jwt.New()
		tok.Set(jwt.IssuedAtKey, now)
		tok.Set(jwt.ExpirationKey, now.Add(5*time.Second))

		if !assert.Error(t, jwt.Validate(tok, jwt.WithMaxDelta(2*time.Second, jwt.ExpirationKey, jwt.IssuedAtKey)), `jwt.Validate should fail`) {
			return
		}

		if !assert.NoError(t, jwt.Validate(tok, jwt.WithMaxDelta(10*time.Second, jwt.ExpirationKey, jwt.IssuedAtKey)), `jwt.Validate should succeed`) {
			return
		}
	})
	t.Run("iat - exp (5 secs) < WithMinDelta(10 secs)", func(t *testing.T) {
		now := time.Now()
		tok := jwt.New()
		tok.Set(jwt.ExpirationKey, now.Add(5*time.Second))
		tok.Set(jwt.IssuedAtKey, now)

		if !assert.Error(t, jwt.Validate(tok, jwt.WithMinDelta(10*time.Second, jwt.ExpirationKey, jwt.IssuedAtKey)), `jwt.Validate should fail`) {
			return
		}
	})
	t.Run("iat - exp (5 secs) > WithMinDelta(10 secs)", func(t *testing.T) {
		now := time.Now()
		tok := jwt.New()
		tok.Set(jwt.ExpirationKey, now.Add(5*time.Second))
		tok.Set(jwt.IssuedAtKey, now)

		if !assert.NoError(t, jwt.Validate(tok, jwt.WithMinDelta(10*time.Second, jwt.ExpirationKey, jwt.IssuedAtKey), jwt.WithAcceptableSkew(5*time.Second)), `jwt.Validate should succeed`) {
			return
		}
	})
	t.Run("now - iat < WithMaxDelta(10 secs)", func(t *testing.T) {
		now := time.Now()
		tok := jwt.New()
		tok.Set(jwt.IssuedAtKey, now)

		if !assert.NoError(t, jwt.Validate(tok, jwt.WithMaxDelta(10*time.Second, "", jwt.IssuedAtKey), jwt.WithClock(jwt.ClockFunc(func() time.Time { return now.Add(5 * time.Second) }))), `jwt.Validate should succeed`) {
			return
		}
	})
	t.Run("invalid claim name (c1)", func(t *testing.T) {
		now := time.Now()
		tok := jwt.New()
		tok.Set("foo", now)
		tok.Set(jwt.ExpirationKey, now.Add(5*time.Second))

		if !assert.Error(t, jwt.Validate(tok, jwt.WithMinDelta(10*time.Second, jwt.ExpirationKey, "foo"), jwt.WithAcceptableSkew(5*time.Second)), `jwt.Validate should fail`) {
			return
		}
	})
	t.Run("invalid claim name (c2)", func(t *testing.T) {
		now := time.Now()
		tok := jwt.New()
		tok.Set(jwt.IssuedAtKey, now)
		tok.Set("foo", now.Add(5*time.Second))

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
		tok := jwt.New()
		tok.Set(`foo`, 1)
		if !assert.NoError(t, jwt.Validate(tok, jwt.WithRequiredClaim("foo")), `jwt.Validate should fail`) {
			return
		}
	})
}

func TestNested(t *testing.T) {
	key, err := jwxtest.GenerateRsaKey()
	if !assert.NoError(t, err, `jwxtest.GenerateRsaKey should succeed`) {
		return
	}

	token := jwt.New()
	token.Set(jwt.IssuerKey, `https://github.com/lestrrat-go/jwx`)

	serialized, err := jwt.NewSerializer().
		Sign(jwa.RS256, key).
		Encrypt(jwa.RSA_OAEP, key.PublicKey, jwa.A256GCM, jwa.NoCompress).
		Serialize(token)

	if !assert.NoError(t, err, `jwt.NewSerializer should succeed`) {
		return
	}

	// First layer should be JWE
	jweMessage := jwe.NewMessage()
	decrypted, err := jwe.Decrypt(serialized, jwa.RSA_OAEP, key, jwe.WithMessage(jweMessage))
	if !assert.NoError(t, err, `jwe.Decrypt should succeed`) {
		return
	}

	// The message should have cty = JWT
	cty := jweMessage.ProtectedHeaders().ContentType()
	if !assert.Equal(t, cty, `JWT`, `cty should be JWT`) {
		return
	}

	// Second layer should JWS.
	jwsMessage := jws.NewMessage()
	verified, err := jws.Verify(decrypted, jwa.RS256, key.PublicKey, jws.WithMessage(jwsMessage))
	if !assert.NoError(t, err, `jws.Verify should succeed`) {
		return
	}

	typ := jwsMessage.Signatures()[0].ProtectedHeaders().Type()
	if !assert.Equal(t, typ, `JWT`, `cty should be JWT`) {
		return
	}

	t.Logf("%s", verified)

	parsed, err := jwt.Parse(serialized,
		jwt.WithPedantic(true),
		jwt.WithVerify(jwa.RS256, key.PublicKey),
		jwt.WithDecrypt(jwa.RSA_OAEP, key),
	)
	if !assert.NoError(t, err, `jwt.Parse with both decryption and verification should succeed`) {
		return
	}
	_ = parsed
}

func TestRFC7797(t *testing.T) {
	key, err := jwxtest.GenerateRsaKey()
	if !assert.NoError(t, err, `jwxtest.GenerateRsaKey should succeed`) {
		return
	}

	hdrs := jws.NewHeaders()
	hdrs.Set("b64", false)
	hdrs.Set("crit", "b64")

	token := jwt.New()
	token.Set(jwt.AudienceKey, `foo`)

	_, err = jwt.Sign(token, jwa.RS256, key, jwt.WithJwsHeaders(hdrs))
	if !assert.Error(t, err, `jwt.Sign should fail`) {
		return
	}
}
