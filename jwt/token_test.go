package jwt_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/internal/json"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
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
			if !assert.NoError(t, h.Set(k, v), `h.Set should succeed for key %#v`, k) {
				return
			}
			got, ok := h.Get(k)
			if !assert.True(t, ok, `h.Get should succeed for key %#v`, k) {
				return
			}
			if !reflect.DeepEqual(v, got) {
				t.Fatalf("Values do not match: (%v, %v)", v, got)
			}
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
			_, ok := h.Get(k)
			if ok {
				t.Fatalf("Getting %s value should have failed", k)
			}
		}
		_, ok := h.Get("default")
		if !ok {
			t.Fatal("Failed to get default value")
		}
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
			getval, ok := tok.Get(k)
			if !assert.True(t, ok, `tok.Get(%s) should succeed`, k) {
				return
			}

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

		m1, err := tok.AsMap(context.TODO())
		if !assert.NoError(t, err, `tok.AsMap should succeed`) {
			return
		}

		m2, err := newtok.AsMap(context.TODO())
		if !assert.NoError(t, err, `tok.AsMap should succeed`) {
			return
		}

		if !assert.Equal(t, m1, m2, `tokens should match`) {
			return
		}
	})
	t.Run("Set/Remove", func(t *testing.T) {
		ctx := context.TODO()

		newtok, err := tok.Clone()
		if !assert.NoError(t, err, `tok.Clone should succeed`) {
			return
		}

		for iter := tok.Iterate(ctx); iter.Next(ctx); {
			pair := iter.Pair()
			newtok.Remove(pair.Key.(string))
		}

		m, err := newtok.AsMap(ctx)
		if !assert.NoError(t, err, `tok.AsMap should succeed`) {
			return
		}

		if !assert.Len(t, m, 0, `toks should have 0 tok`) {
			return
		}

		for iter := tok.Iterate(ctx); iter.Next(ctx); {
			pair := iter.Pair()
			if !assert.NoError(t, newtok.Set(pair.Key.(string), pair.Value), `newtok.Set should succeed`) {
				return
			}
		}
	})
}
