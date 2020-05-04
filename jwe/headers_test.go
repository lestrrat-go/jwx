package jwe_test

import (
	"context"
	"testing"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"
)

func TestHeaders(t *testing.T) {
	t.Run("Set/Get", func(t *testing.T) {
		h := jwe.NewHeaders()

		data := map[string]struct {
			Value    interface{}
			Expected interface{}
		}{
			"kid":     {Value: "kid blah"},
			"enc":     {Value: jwa.A128GCM},
			"cty":     {Value: "application/json"},
			"typ":     {Value: "typ blah"},
			"x5t":     {Value: "x5t blah"},
			"x5t#256": {Value: "x5t#256 blah"},
			"crit":    {Value: []string{"crit blah"}},
			"jku":     {Value: "http://github.com/lestrrat-go/jwx"},
			"x5u":     {Value: "http://github.com/lestrrat-go/jwx"},
		}

		for name, testcase := range data {
			h.Set(name, testcase.Value)
			got, ok := h.Get(name)
			if !assert.True(t, ok, "value should exist") {
				return
			}

			expected := testcase.Expected
			if expected == nil {
				expected = testcase.Value
			}
			if !assert.Equal(t, expected, got, "value should match") {
				return
			}
		}
	})
	t.Run("Encode", func(t *testing.T) {
		h1 := jwe.NewHeaders()
		h1.Set(jwe.AlgorithmKey, jwa.A128GCMKW)
		h1.Set("foo", "bar")

		buf, err := h1.Encode()
		if !assert.NoError(t, err, `h1.Encode should succeed`) {
			return
		}

		h2 := jwe.NewHeaders()
		if !assert.NoError(t, h2.Decode(buf), `h2.Decode should succeed`) {
			return
		}

		if !assert.Equal(t, h1, h2, `objects should match`) {
			return
		}
	})

	t.Run("Iterator", func(t *testing.T) {
		expected := map[string]interface{}{}
		v := jwe.NewHeaders()
		t.Run("Iterate", func(t *testing.T) {
			seen := make(map[string]interface{})
			for iter := v.Iterate(context.TODO()); iter.Next(context.TODO()); {
				pair := iter.Pair()
				seen[pair.Key.(string)] = pair.Value

				getV, ok := v.Get(pair.Key.(string))
				if !assert.True(t, ok, `v.Get should succeed for key %#v`, pair.Key) {
					return
				}
				if !assert.Equal(t, pair.Value, getV, `pair.Value should match value from v.Get()`) {
					return
				}
			}
			if !assert.Equal(t, expected, seen, `values should match`) {
				return
			}
		})
		t.Run("Walk", func(t *testing.T) {
			seen := make(map[string]interface{})
			v.Walk(context.TODO(), jwk.HeaderVisitorFunc(func(key string, value interface{}) error {
				seen[key] = value
				return nil
			}))
			if !assert.Equal(t, expected, seen, `values should match`) {
				return
			}
		})
		t.Run("AsMap", func(t *testing.T) {
			seen, err := v.AsMap(context.TODO())
			if !assert.NoError(t, err, `v.AsMap should succeed`) {
				return
			}
			if !assert.Equal(t, expected, seen, `values should match`) {
				return
			}
		})
	})
}
