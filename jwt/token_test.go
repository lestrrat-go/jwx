package jwt_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/internal/json"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	tokenTime = 233431200
)

var zeroval reflect.Value
var expectedTokenTime = time.Unix(tokenTime, 0).UTC()

func TestHeader(t *testing.T) {
	t.Parallel()
	values := map[string]interface{}{
		jwt.AudienceKey:   []string{"developers", "secops", "tac"},
		jwt.ExpirationKey: expectedTokenTime,
		jwt.IssuedAtKey:   expectedTokenTime,
		jwt.IssuerKey:     "http://www.example.com",
		jwt.JwtIDKey:      "e9bc097a-ce51-4036-9562-d2ade882db0d",
		jwt.NotBeforeKey:  expectedTokenTime,
		jwt.SubjectKey:    "unit test",
	}

	t.Run("Roundtrip", func(t *testing.T) {
		t.Parallel()
		h := jwt.New()
		for k, v := range values {
			require.NoError(t, h.Set(k, v), `h.Set should succeed for key %#v`, k)

			var got interface{}
			require.NoError(t, h.Get(k, &got), `h.Get should succeed for key %#v`, k)
			require.Equal(t, v, got, `values from h.Set and h.Get should match`)
		}
	})

	t.Run("RoundtripError", func(t *testing.T) {
		t.Parallel()
		type dummyStruct struct {
			dummy1 int
			dummy2 float64
		}
		dummy := &dummyStruct{1, 3.4}

		values := map[string]interface{}{
			jwt.AudienceKey:   dummy,
			jwt.ExpirationKey: dummy,
			jwt.IssuedAtKey:   dummy,
			jwt.IssuerKey:     dummy,
			jwt.JwtIDKey:      dummy,
			jwt.NotBeforeKey:  dummy,
			jwt.SubjectKey:    dummy,
		}

		h := jwt.New()
		for k, v := range values {
			err := h.Set(k, v)
			if err == nil {
				t.Fatalf("Setting %s value should have failed", k)
			}
		}
		err := h.Set("default", dummy) // private params
		if err != nil {
			t.Fatalf("Setting %s value failed", "default")
		}
		for k := range values {
			require.False(t, h.Has(k), "getting %s value should have failed", k)
		}
		require.True(t, h.Has("default"), "getting 'default' should succeed")
		var v interface{}
		require.NoError(t, h.Get("default", &v), "getting 'default' should succeed")
		require.Equal(t, dummy, v, `values for 'default' should match`)
	})

	t.Run("GetError", func(t *testing.T) {
		t.Parallel()
		h := jwt.New()
		issuer := h.Issuer()
		if issuer != "" {
			t.Fatalf("Get Issuer should return empty string")
		}
		jwtID := h.JwtID()
		if jwtID != "" {
			t.Fatalf("Get JWT Id should return empty string")
		}
	})
}

func TestTokenMarshal(t *testing.T) {
	t.Parallel()
	t1 := jwt.New()
	err := t1.Set(jwt.JwtIDKey, "AbCdEfG")
	if err != nil {
		t.Fatalf("Failed to set JWT ID: %s", err.Error())
	}
	err = t1.Set(jwt.SubjectKey, "foobar@example.com")
	if err != nil {
		t.Fatalf("Failed to set Subject: %s", err.Error())
	}

	// Silly fix to remove monotonic element from time.Time obtained
	// from time.Now(). Without this, the equality comparison goes
	// ga-ga for golang tip (1.9)
	now := time.Unix(time.Now().Unix(), 0)
	err = t1.Set(jwt.IssuedAtKey, now.Unix())
	if err != nil {
		t.Fatalf("Failed to set IssuedAt: %s", err.Error())
	}
	err = t1.Set(jwt.NotBeforeKey, now.Add(5*time.Second))
	if err != nil {
		t.Fatalf("Failed to set NotBefore: %s", err.Error())
	}
	err = t1.Set(jwt.ExpirationKey, now.Add(10*time.Second).Unix())
	if err != nil {
		t.Fatalf("Failed to set Expiration: %s", err.Error())
	}
	err = t1.Set(jwt.AudienceKey, []string{"devops", "secops", "tac"})
	if err != nil {
		t.Fatalf("Failed to set audience: %s", err.Error())
	}
	err = t1.Set("custom", "MyValue")
	if err != nil {
		t.Fatalf(`Failed to set private claim "custom": %s`, err.Error())
	}
	jsonbuf1, err := json.MarshalIndent(t1, "", "  ")
	if err != nil {
		t.Fatalf("JSON Marshal failed: %s", err.Error())
	}

	t2 := jwt.New()
	if !assert.NoError(t, json.Unmarshal(jsonbuf1, t2), `json.Unmarshal should succeed`) {
		return
	}

	if !assert.Equal(t, t1, t2, "tokens should match") {
		return
	}

	_, err = json.MarshalIndent(t2, "", "  ")
	if err != nil {
		t.Fatalf("JSON marshal error: %s", err.Error())
	}
}

func TestToken(t *testing.T) {
	tok := jwt.New()

	def := map[string]struct {
		Value  interface{}
		Method string
	}{
		jwt.AudienceKey: {
			Method: "Audience",
			Value:  []string{"developers", "secops", "tac"},
		},
		jwt.ExpirationKey: {
			Method: "Expiration",
			Value:  expectedTokenTime,
		},
		jwt.IssuedAtKey: {
			Method: "IssuedAt",
			Value:  expectedTokenTime,
		},
		jwt.IssuerKey: {
			Method: "Issuer",
			Value:  "http://www.example.com",
		},
		jwt.JwtIDKey: {
			Method: "JwtID",
			Value:  "e9bc097a-ce51-4036-9562-d2ade882db0d",
		},
		jwt.NotBeforeKey: {
			Method: "NotBefore",
			Value:  expectedTokenTime,
		},
		jwt.SubjectKey: {
			Method: "Subject",
			Value:  "unit test",
		},
		"myClaim": {
			Value: "hello, world",
		},
	}

	t.Run("Set", func(t *testing.T) {
		for k, kdef := range def {
			if !assert.NoError(t, tok.Set(k, kdef.Value), `tok.Set(%s) should succeed`, k) {
				return
			}
		}
	})
	t.Run("Get", func(t *testing.T) {
		rv := reflect.ValueOf(tok)
		for k, kdef := range def {
			var getval interface{}
			require.NoError(t, tok.Get(k, &getval), `tok.Get(%s) should succeed`, k)

			if mname := kdef.Method; mname != "" {
				method := rv.MethodByName(mname)
				if !assert.NotEqual(t, zeroval, method, `method %s should not be zero value`, mname) {
					return
				}

				retvals := method.Call(nil)
				if !assert.Len(t, retvals, 1, `should have exactly one return value`) {
					return
				}

				if !assert.Equal(t, getval, retvals[0].Interface(), `values should match`) {
					return
				}
			}
		}
	})
	t.Run("Roundtrip", func(t *testing.T) {
		buf, err := json.Marshal(tok)
		if !assert.NoError(t, err, `json.Marshal should succeed`) {
			return
		}

		newtok, err := jwt.ParseInsecure(buf)
		if !assert.NoError(t, err, `jwt.Parse should succeed`) {
			return
		}

		require.True(t, jwt.Equal(tok, newtok), `tokens should match`)
	})
	t.Run("Set/Remove", func(t *testing.T) {
		newtok, err := tok.Clone()
		if !assert.NoError(t, err, `tok.Clone should succeed`) {
			return
		}

		for _, k := range tok.Keys() {
			newtok.Remove(k)
		}

		require.Len(t, newtok.Keys(), 0, `newtok should have 0 fields`)
	})
}
