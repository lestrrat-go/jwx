package jwt_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/internal/json"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/require"
)

func TestClaimsNestedAccess(t *testing.T) {
	t.Parallel()
	tok := jwt.New()
	require.NoError(t, tok.Set(jwt.IssuerKey, "https://example.com"))
	require.NoError(t, tok.Set(jwt.SubjectKey, "alice"))
	require.NoError(t, tok.Set("custom", "value"))

	done := make(chan struct{})
	go func() {
		defer close(done)
		for k := range tok.Claims() {
			// Calls that acquire the token's lock from within the yield
			// closure must not deadlock — Claims() must release the lock
			// before yielding.
			_, _ = tok.Field(k)
			_ = tok.Has(k)
			require.NoError(t, tok.Set("mutated", k))
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Claims() iteration deadlocked on nested token access")
	}
}

const (
	tokenTime = 233431200
)

var zeroval reflect.Value
var expectedTokenTime = time.Unix(tokenTime, 0).UTC()

func TestHeader(t *testing.T) {
	t.Parallel()
	values := map[string]any{
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
			got, ok := h.Field(k)
			require.True(t, ok, `h.Field should succeed for key %#v`, k)
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

		values := map[string]any{
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
			_, ok := h.Field(k)
			require.False(t, ok, `Getting %s value should have failed`, k)
		}
		tmp, ok := h.Field("default")
		require.True(t, ok, `Getting %s value should have succeeded`, "default")
		_ = tmp
	})

	t.Run("GetError", func(t *testing.T) {
		t.Parallel()
		h := jwt.New()
		issuer, ok := h.Issuer()
		require.False(t, ok, `Issuer should not be set`)
		require.Empty(t, issuer, `Issuer should be empty`)
		jwtID, ok := h.JwtID()
		require.False(t, ok, `JwtID should not be set`)
		require.Empty(t, jwtID, `JwtID should be empty`)
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
	require.NoError(t, json.Unmarshal(jsonbuf1, t2), `json.Unmarshal should succeed`)
	require.Equal(t, t1, t2, "tokens should match")
	_, err = json.MarshalIndent(t2, "", "  ")
	require.NoError(t, err, `json.MarshalIndent should succeed`)
}

func TestToken(t *testing.T) {
	tok := jwt.New()

	def := map[string]struct {
		Value  any
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
			require.NoError(t, tok.Set(k, kdef.Value), `tok.Set(%s) should succeed`, k)
		}
	})
	t.Run("Field", func(t *testing.T) {
		rv := reflect.ValueOf(tok)
		for k, kdef := range def {
			getval, ok := tok.Field(k)
			require.True(t, ok, `tok.Field(%s) should succeed`, k)

			if mname := kdef.Method; mname != "" {
				method := rv.MethodByName(mname)
				require.NotEqual(t, zeroval, method, `method %s should not be zero value`, mname)
				retvals := method.Call(nil)
				require.Len(t, retvals, 2, `should have exactly one return value`)
				require.Equal(t, getval, retvals[0].Interface(), `values should match`)
			}
		}
	})
	t.Run("Roundtrip", func(t *testing.T) {
		buf, err := json.Marshal(tok)
		require.NoError(t, err, `json.Marshal should succeed`)
		newtok, err := jwt.ParseInsecure(buf)
		require.NoError(t, err, `jwt.Parse should succeed`)
		require.True(t, jwt.Equal(tok, newtok), `tokens should match`)
	})
	t.Run("Set/Remove", func(t *testing.T) {
		newtok, err := tok.Clone()
		require.NoError(t, err, `tok.Clone should succeed`)
		for _, k := range tok.Keys() {
			newtok.Remove(k)
		}

		require.Len(t, newtok.Keys(), 0, `toks should have 0 tok`)
		for _, k := range tok.Keys() {
			v, ok := tok.Field(k)
			require.True(t, ok, `tok.Field(%s) should succeed`, k)
			require.NoError(t, newtok.Set(k, v), `newtok.Set should succeed`)
		}
	})
}

func TestUnmarshalResetsPrivateClaims(t *testing.T) {
	t.Parallel()
	t.Run("direct UnmarshalJSON", func(t *testing.T) {
		t.Parallel()
		tok := jwt.New()
		require.NoError(t, json.Unmarshal([]byte(`{"role":"admin","sub":"x"}`), tok))
		v, ok := tok.Field("role")
		require.True(t, ok, `role claim should be present after first unmarshal`)
		require.Equal(t, "admin", v)

		// Reuse the same token instance for a payload that omits "role".
		require.NoError(t, json.Unmarshal([]byte(`{"sub":"y"}`), tok))
		_, ok = tok.Field("role")
		require.False(t, ok, `stale private claim "role" must be cleared on reuse`)
		sub, ok := tok.Subject()
		require.True(t, ok, `sub claim should be present after second unmarshal`)
		require.Equal(t, "y", sub)
	})
	t.Run("Parse with WithToken", func(t *testing.T) {
		t.Parallel()
		key := []byte("0123456789abcdef")

		t1 := jwt.New()
		require.NoError(t, t1.Set("role", "admin"))
		require.NoError(t, t1.Set(jwt.SubjectKey, "x"))
		signed1, err := jwt.Sign(t1, jwt.WithKey(jwa.HS256(), key))
		require.NoError(t, err, `jwt.Sign should succeed`)

		t2 := jwt.New()
		require.NoError(t, t2.Set(jwt.SubjectKey, "y"))
		signed2, err := jwt.Sign(t2, jwt.WithKey(jwa.HS256(), key))
		require.NoError(t, err, `jwt.Sign should succeed`)

		dst := jwt.New()
		_, err = jwt.Parse(signed1, jwt.WithKey(jwa.HS256(), key), jwt.WithToken(dst))
		require.NoError(t, err, `jwt.Parse should succeed`)
		v, ok := dst.Field("role")
		require.True(t, ok, `role claim should be present after first parse`)
		require.Equal(t, "admin", v)

		// Reuse the same destination token for a payload without "role".
		_, err = jwt.Parse(signed2, jwt.WithKey(jwa.HS256(), key), jwt.WithToken(dst))
		require.NoError(t, err, `jwt.Parse should succeed`)
		_, ok = dst.Field("role")
		require.False(t, ok, `stale private claim "role" must be cleared on reuse`)
		sub, ok := dst.Subject()
		require.True(t, ok, `sub claim should be present after second parse`)
		require.Equal(t, "y", sub)
	})
}
