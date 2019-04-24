package jwt_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/stretchr/testify/assert"
)

func TestJWTParse(t *testing.T) {

	alg := jwa.RS256
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("Failed to generate RSA key")
	}
	t1 := jwt.New()
	signed, err := t1.Sign(alg, key)
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

	t1 := jwt.New()
	signed, err := t1.Sign(alg, key)

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

		if !assert.NoError(t, token.Verify(args...), "token.Verify should validate tokens in the same second they are created") {
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
		Expected     func() *jwt.Token
		ExpectedJSON string
	}{
		{
			Title:  "single aud",
			Source: `{"aud":"foo"}`,
			Expected: func() *jwt.Token {
				t := jwt.New()
				t.Set("aud", "foo")
				return t
			},
			ExpectedJSON: `{"aud":["foo"]}`,
		},
		{
			Title:  "multiple aud's",
			Source: `{"aud":["foo","bar"]}`,
			Expected: func() *jwt.Token {
				t := jwt.New()
				t.Set("aud", []string{"foo", "bar"})
				return t
			},
			ExpectedJSON: `{"aud":["foo","bar"]}`,
		},
		{
			Title:  "issuedAt",
			Source: `{"` + jwt.IssuedAtKey + `":` + aLongLongTimeAgoString + `}`,
			Expected: func() *jwt.Token {
				t := jwt.New()
				t.Set(jwt.IssuedAtKey, aLongLongTimeAgo)
				return t
			},
			ExpectedJSON: `{"` + jwt.IssuedAtKey + `":` + aLongLongTimeAgoString + `}`,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.Title, func(t *testing.T) {
			var token jwt.Token
			if !assert.NoError(t, json.Unmarshal([]byte(tc.Source), &token), `json.Unmarshal should succeed`) {
				return
			}
			if !assert.Equal(t, tc.Expected(), &token, `token should match expected value`) {
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

		s, err := tok.Sign(jwa.ES256, priv)
		if !assert.NoError(t, err) {
			return
		}

		if _, err = jws.Verify([]byte(s), jwa.ES256, pub); !assert.NoError(t, err, `test should pass (run %d)`, i) {
			return
		}
	}
}

func TestUnmarshalJSON(t *testing.T) {

	t.Run("Unmarshal audience with multiple values", func(t *testing.T) {
		var t1 jwt.Token
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
