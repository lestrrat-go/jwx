package jwe_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/lestrrat-go/jwx/buffer"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"
)

func TestHeaders(t *testing.T) {
	rawKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if !assert.NoError(t, err, `ecdsa.GenerateKey should succeed`) {
		return
	}
	privKey, err := jwk.New(rawKey)
	if !assert.NoError(t, err, `jwk.New should succeed`) {
		return
	}

	pubKey, err := jwk.New(rawKey.PublicKey)
	if !assert.NoError(t, err, `jwk.PublicKey should succeed`) {
		return
	}

	data := []struct {
		Key      string
		Value    interface{}
		Expected interface{}
	}{
		{Key: jwe.AgreementPartyUInfoKey, Value: []byte("apu foobarbaz"), Expected: buffer.Buffer("apu foobarbaz")},
		{Key: jwe.AgreementPartyVInfoKey, Value: []byte("apv foobarbaz"), Expected: buffer.Buffer("apv foobarbaz")},
		{Key: jwe.CompressionKey, Value: jwa.Deflate},
		{Key: jwe.ContentEncryptionKey, Value: jwa.A128GCM},
		{Key: jwe.ContentTypeKey, Value: "application/json"},
		{Key: jwe.CriticalKey, Value: []string{"crit blah"}},
		{Key: jwe.EphemeralPublicKeyKey, Value: pubKey},
		{Key: jwe.JWKKey, Value: privKey},
		{Key: jwe.JWKSetURLKey, Value: "http://github.com/lestrrat-go/jwx"},
		{Key: jwe.KeyIDKey, Value: "kid blah"},
		{Key: jwe.TypeKey, Value: "typ blah"},
		{Key: jwe.X509CertThumbprintKey, Value: "x5t blah"},
		{Key: jwe.X509CertThumbprintS256Key, Value: "x5t#256 blah"},
		{Key: jwe.X509URLKey, Value: "http://github.com/lestrrat-go/jwx"},
	}

	base := jwe.NewHeaders()

	t.Run("Set values", func(t *testing.T) {
		for _, tc := range data {
			if !assert.NoError(t, base.Set(tc.Key, tc.Value), "Headers.Set should succeed") {
				return
			}
		}
	})

	t.Run("Set/Get", func(t *testing.T) {
		h := base
		for _, tc := range data {
			got, ok := h.Get(tc.Key)
			if !assert.True(t, ok, "value for %s should exist", tc.Key) {
				return
			}

			expected := tc.Expected
			if expected == nil {
				expected = tc.Value
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
