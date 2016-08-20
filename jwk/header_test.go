package jwk

import (
	"fmt"
	"net/url"
	"testing"

	"github.com/lestrrat/go-jwx/jwa"
	"github.com/stretchr/testify/assert"
)

func TestHeader(t *testing.T) {
	values := map[string]interface{}{
		"kid":     "helloworld01",
		"kty":     jwa.RSA,
		"key_ops": []KeyOperation{KeyOpSign},
		"use":     "sig",
		"x5t":     "thumbprint",
		"x5t#256": "thumbprint256",
		"x5c":     []string{"cert1", "cert2"},
	}

	h := &EssentialHeader{}

	for k, v := range values {
		if !assert.NoError(t, h.Set(k, v), "Set works for '%s'", k) {
			return
		}

		got, err := h.Get(k)
		if !assert.NoError(t, err, "Get works for '%s'", k) {
			return
		}

		if !assert.Equal(t, v, got, "values match '%s'", k) {
			return
		}

		err = h.Set(k, v)
		if !assert.NoError(t, err, "Set works for '%s'", k) {
			return
		}
	}
}

func TestHeader_Alg(t *testing.T) {
	h := &EssentialHeader{}

	for _, value := range []interface{}{jwa.RS256, jwa.RSA1_5} {
		if !assert.NoError(t, h.Set("alg", value), "Set for alg should succeed") {
			return
		}

		got, err := h.Get("alg")
		if !assert.NoError(t, err, "Get for alg should succeed") {
			return
		}

		if !assert.Equal(t, value.(fmt.Stringer).String(), got, "values match") {
			return
		}
	}
}

func TestHeader_Kty(t *testing.T) {
	h := &EssentialHeader{}

	for _, value := range []interface{}{jwa.RSA, "RSA"} {
		if !assert.NoError(t, h.Set("kty", value), "Set for kty should succeed") {
			return
		}

		got, err := h.Get("kty")
		if !assert.NoError(t, err, "Get for kty should succeed") {
			return
		}

		var s string
		switch value.(type) {
		case jwa.KeyType:
			s = value.(jwa.KeyType).String()
		case string:
			s = value.(string)
		}

		if !assert.Equal(t, jwa.KeyType(s), got, "values match") {
			return
		}
	}
}

func TestHeader_X5u(t *testing.T) {
	h := &EssentialHeader{}
	us := "https://eample.domain/x509.pem"
	u, _ := url.Parse(us)

	for _, value := range []interface{}{us, u} {
		if !assert.NoError(t, h.Set("x5u", value), "Set for x5u should succeed") {
			return
		}

		got, err := h.Get("x5u")
		if !assert.NoError(t, err, "Get for x5u should succeed") {
			return
		}

		var s string
		switch value.(type) {
		case *url.URL:
			s = value.(*url.URL).String()
		case string:
			s = value.(string)
		}

		if !assert.Equal(t, s, got.(*url.URL).String(), "values match") {
			return
		}
	}
}
