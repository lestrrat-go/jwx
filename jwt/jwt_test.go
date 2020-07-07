package jwt_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWTParse(t *testing.T) {
	alg := jwa.RS256
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("Failed to generate RSA key")
	}
	t1 := jwt.New()
	signed, err := jwt.Sign(t1, alg, key)
	if err != nil {
		t.Fatal("Failed to sign JWT")
	}

	t.Run("Parse (no signature verification)", func(t *testing.T) {
		t2, err := jwt.Parse(bytes.NewReader(signed))
		if !assert.NoError(t, err, `jwt.Parse should succeed`) {
			return
		}
		if !assert.Equal(t, t1, t2, `t1 == t2`) {
			return
		}
	})
	t.Run("ParseString (no signature verification)", func(t *testing.T) {
		t2, err := jwt.ParseString(string(signed))
		if !assert.NoError(t, err, `jwt.ParseString should succeed`) {
			return
		}
		if !assert.Equal(t, t1, t2, `t1 == t2`) {
			return
		}
	})
	t.Run("ParseBytes (no signature verification)", func(t *testing.T) {
		t2, err := jwt.ParseBytes(signed)
		if !assert.NoError(t, err, `jwt.ParseBytes should succeed`) {
			return
		}
		if !assert.Equal(t, t1, t2, `t1 == t2`) {
			return
		}
	})
	t.Run("Parse (correct signature key)", func(t *testing.T) {
		t2, err := jwt.Parse(bytes.NewReader(signed), jwt.WithVerify(alg, &key.PublicKey))
		if !assert.NoError(t, err, `jwt.Parse should succeed`) {
			return
		}
		if !assert.Equal(t, t1, t2, `t1 == t2`) {
			return
		}
	})
	t.Run("parse (wrong signature algorithm)", func(t *testing.T) {
		_, err := jwt.Parse(bytes.NewReader(signed), jwt.WithVerify(jwa.RS512, &key.PublicKey))
		if !assert.Error(t, err, `jwt.Parse should fail`) {
			return
		}
	})
	t.Run("parse (wrong signature key)", func(t *testing.T) {
		pubkey := key.PublicKey
		pubkey.E = 0 // bogus value
		_, err := jwt.Parse(bytes.NewReader(signed), jwt.WithVerify(alg, &pubkey))
		if !assert.Error(t, err, `jwt.Parse should fail`) {
			return
		}
	})
}

func TestJWTParseVerify(t *testing.T) {
	alg := jwa.RS256
	key, err := rsa.GenerateKey(rand.Reader, 2048)
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

	t.Run("ParseVerify(old API)", func(t *testing.T) {
		t.Run("parse (no signature verification)", func(t *testing.T) {
			_, err := jwt.ParseVerify(bytes.NewReader(signed), "", nil)
			if !assert.Error(t, err, `jwt.ParseVerify should fail`) {
				return
			}
		})
		t.Run("parse (correct signature key)", func(t *testing.T) {
			t2, err := jwt.ParseVerify(bytes.NewReader(signed), alg, &key.PublicKey)
			if !assert.NoError(t, err, `jwt.ParseVerify should succeed`) {
				return
			}
			if !assert.Equal(t, t1, t2, `t1 == t2`) {
				return
			}
		})
		t.Run("parse (wrong signature algorithm)", func(t *testing.T) {
			_, err := jwt.ParseVerify(bytes.NewReader(signed), jwa.RS512, &key.PublicKey)
			if !assert.Error(t, err, `jwt.ParseVerify should fail`) {
				return
			}
		})
		t.Run("parse (wrong signature key)", func(t *testing.T) {
			pubkey := key.PublicKey
			pubkey.E = 0 // bogus value
			_, err := jwt.ParseVerify(bytes.NewReader(signed), alg, &pubkey)
			if !assert.Error(t, err, `jwt.ParseVerify should fail`) {
				return
			}
		})
	})
	t.Run("Parse (w/jwk.Set)", func(t *testing.T) {
		t.Run("Automatically pick a key from set", func(t *testing.T) {
			pubkey := jwk.NewRSAPublicKey()
			if !assert.NoError(t, pubkey.FromRaw(&key.PublicKey)) {
				return
			}

			pubkey.Set(jwk.KeyIDKey, kid)
			t2, err := jwt.Parse(bytes.NewReader(signed), jwt.WithKeySet(&jwk.Set{Keys: []jwk.Key{pubkey}}))
			if !assert.NoError(t, err, `jwt.Parse with key set should succeed`) {
				return
			}
			if !assert.Equal(t, t1, t2, `t1 == t2`) {
				return
			}
		})
	})

	// This is a test to check if we allow alg: none in the protected header section.
	// But in truth, since we delegate everything to jws.Verify anyways, it's really
	// a test to see if jws.Verify returns an error if alg: none is specified in the
	// header section. Move this test to jws if need be.
	t.Run("Check alg=none", func(t *testing.T) {
		// Create a signed payload, but use alg=none
		_, payload, signature, err := jws.SplitCompact(bytes.NewReader(signed))
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

		_, err = jwt.Parse(bytes.NewReader(signedButNot), jwt.WithKeySet(&jwk.Set{Keys: []jwk.Key{pubkey}}))
		// This should fail
		if !assert.Error(t, err, `jwt.Parse with key set + alg=none should fail`) {
			return
		}
	})
}

func TestVerifyClaims(t *testing.T) {
	// GitHub issue #37: tokens are invalid in the second they are created (because Now() is not after IssuedAt())
	t.Run(jwt.IssuedAtKey+"+skew", func(t *testing.T) {
		token := jwt.New()
		now := time.Now().UTC()
		token.Set(jwt.IssuedAtKey, now)

		const DefaultSkew = 0

		args := []jwt.Option{
			jwt.WithClock(jwt.ClockFunc(func() time.Time { return now })),
			jwt.WithAcceptableSkew(DefaultSkew),
		}

		if !assert.NoError(t, jwt.Verify(token, args...), "token.Verify should validate tokens in the same second they are created") {
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
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if !assert.NoError(t, err) {
		return
	}

	pub := &priv.PublicKey
	if !assert.NoError(t, err) {
		return
	}
	for i := 0; i < 1000; i++ {
		tok := jwt.New()

		s, err := jwt.Sign(tok, jwa.ES256, priv)
		if !assert.NoError(t, err) {
			return
		}

		if _, err = jws.Verify(s, jwa.ES256, pub); !assert.NoError(t, err, `test should pass (run %d)`, i) {
			return
		}
	}
}

func TestUnmarshalJSON(t *testing.T) {
	t.Run("Unmarshal audience with multiple values", func(t *testing.T) {
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
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tok := jwt.New()
	_, err = jwt.Sign(tok, jwa.SignatureAlgorithm("BOGUS"), priv)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid value for alg key")

	_, err = jwt.Sign(tok, jwa.ES256, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing private key")
}

func TestSignWithKey(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.Nil(t, err)

	key := jwk.NewRSAPrivateKey()
	err = key.FromRaw(priv)
	assert.Nil(t, err)

	key.Set(jwk.KeyIDKey, "test")
	key.Set(jwk.AlgorithmKey, jwa.RS256)

	tok := jwt.New()
	signed, err := jwt.SignWithKey(tok, key)
	assert.Nil(t, err)

	header, err := jws.ParseString(string(signed))
	signatures := header.LookupSignature("test")
	assert.Len(t, signatures, 1)
}
