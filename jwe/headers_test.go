package jwe_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/lestrrat-go/jwx/v2/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
)

var zeroval reflect.Value

func TestHeaders(t *testing.T) {
	certSrc := []string{
		"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",
	}
	var certs cert.Chain
	for _, src := range certSrc {
		_ = certs.AddString(src)
	}

	rawKey, err := jwxtest.GenerateEcdsaKey(jwa.P521)
	if !assert.NoError(t, err, `jwxtest.GenerateEcdsaKey should succeed`) {
		return
	}
	privKey, err := jwk.FromRaw(rawKey)
	if !assert.NoError(t, err, `jwk.FromRaw should succeed`) {
		return
	}

	pubKey, err := jwk.FromRaw(rawKey.PublicKey)
	if !assert.NoError(t, err, `jwk.FromRaw should succeed`) {
		return
	}

	data := []struct {
		Key      string
		Value    interface{}
		Expected interface{}
		Method   string
	}{
		{
			Key:    jwe.AgreementPartyUInfoKey,
			Value:  []byte("apu foobarbaz"),
			Method: "AgreementPartyUInfo",
		},
		{Key: jwe.AgreementPartyVInfoKey, Value: []byte("apv foobarbaz")},
		{Key: jwe.CompressionKey, Value: jwa.Deflate},
		{Key: jwe.ContentEncryptionKey, Value: jwa.A128GCM},
		{
			Key:    jwe.ContentTypeKey,
			Value:  "application/json",
			Method: "ContentType",
		},
		{
			Key:    jwe.CriticalKey,
			Value:  []string{"crit blah"},
			Method: "Critical",
		},
		{
			Key:    jwe.EphemeralPublicKeyKey,
			Value:  pubKey,
			Method: "EphemeralPublicKey",
		},
		{
			Key:    jwe.JWKKey,
			Value:  privKey,
			Method: "JWK",
		},
		{
			Key:    jwe.JWKSetURLKey,
			Value:  "http://github.com/lestrrat-go/jwx/v2",
			Method: "JWKSetURL",
		},
		{
			Key:    jwe.KeyIDKey,
			Value:  "kid blah",
			Method: "KeyID",
		},
		{
			Key:    jwe.TypeKey,
			Value:  "typ blah",
			Method: "Type",
		},
		{
			Key:    jwe.X509CertChainKey,
			Value:  &certs,
			Method: "X509CertChain",
		},
		{
			Key:    jwe.X509CertThumbprintKey,
			Value:  "x5t blah",
			Method: "X509CertThumbprint",
		},
		{
			Key:    jwe.X509CertThumbprintS256Key,
			Value:  "x5t#256 blah",
			Method: "X509CertThumbprintS256",
		},
		{
			Key:    jwe.X509URLKey,
			Value:  "http://github.com/lestrrat-go/jwx/v2",
			Method: "X509URL",
		},
		{Key: "private", Value: "boofoo"},
	}

	base := jwe.NewHeaders()

	t.Run("Set values", func(t *testing.T) {
		// DO NOT RUN THIS IN PARALLEL. THIS IS AN INITIALIZER
		for _, tc := range data {
			if !assert.NoError(t, base.Set(tc.Key, tc.Value), "Headers.Set should succeed") {
				return
			}
		}
	})

	t.Run("Set/Get", func(t *testing.T) {
		h := jwe.NewHeaders()
		ctx := context.Background()

		for iter := base.Iterate(ctx); iter.Next(ctx); {
			pair := iter.Pair()
			if !assert.NoError(t, h.Set(pair.Key.(string), pair.Value), `h.Set should be successful`) {
				return
			}
		}
		for _, tc := range data {
			var values []interface{}
			viaGet, ok := h.Get(tc.Key)
			if !assert.True(t, ok, "value for %s should exist", tc.Key) {
				return
			}
			values = append(values, viaGet)

			if method := tc.Method; method != "" {
				m := reflect.ValueOf(h).MethodByName(method)
				if !assert.NotEqual(t, m, zeroval, "method %s should be available", method) {
					return
				}

				ret := m.Call(nil)
				if !assert.Len(t, ret, 1, `should get exactly 1 value as return value`) {
					return
				}
				values = append(values, ret[0].Interface())
			}

			expected := tc.Expected
			if expected == nil {
				expected = tc.Value
			}
			for i, got := range values {
				if !assert.Equal(t, expected, got, "value %d should match", i) {
					return
				}
			}
		}
	})
	t.Run("PrivateParams", func(t *testing.T) {
		h := base
		pp, err := h.AsMap(context.Background())
		if !assert.NoError(t, err, `h.AsMap should succeed`) {
			return
		}

		v, ok := pp["private"]
		if !assert.True(t, ok, "key 'private' should exists") {
			return
		}

		if !assert.Equal(t, v, "boofoo", "value for 'private' should match") {
			return
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
		for _, tc := range data {
			v := tc.Value
			if expected := tc.Expected; expected != nil {
				v = expected
			}
			expected[tc.Key] = v
		}

		v := base
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
			m, err := v.AsMap(context.TODO())
			if !assert.NoError(t, err, `v.AsMap should succeed`) {
				return
			}
			if !assert.Equal(t, expected, m, `values should match`) {
				return
			}
		})
		t.Run("Remove", func(t *testing.T) {
			h := base
			for iter := h.Iterate(context.TODO()); iter.Next(context.TODO()); {
				pair := iter.Pair()
				h.Remove(pair.Key.(string))
			}

			m, err := h.AsMap(context.TODO())
			if !assert.NoError(t, err, `h.AsMap should succeed`) {
				return
			}
			if !assert.Len(t, m, 0, `len should be zero`) {
				return
			}
		})
	})
}
