package jwk_test

import (
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"
)

func TestParameter(t *testing.T) {
	t.Run("Rountrip", func(t *testing.T) {
		values := map[string]interface{}{
			jwk.KeyIDKey:                  "helloworld01",
			jwk.KeyTypeKey:                jwa.RSA,
			jwk.KeyOpsKey:                 []jwk.KeyOperation{jwk.KeyOpSign},
			jwk.KeyUsageKey:               "sig",
			jwk.X509CertThumbprintKey:     "thumbprint",
			jwk.X509CertThumbprintS256Key: "thumbprint256",
			jwk.X509URLKey:                "cert1",
		}

		var h jwk.StandardParameters
		for k, v := range values {
			if !assert.NoError(t, h.Set(k, v), "Set works for '%s'", k) {
				return
			}

			got, ok := h.Get(k)
			if !assert.True(t, ok, "Get works for '%s'", k) {
				return
			}

			if !assert.Equal(t, v, got, "values match '%s'", k) {
				return
			}

			if !assert.NoError(t, h.Set(k, v), "Set works for '%s'", k) {
				return
			}
		}
	})

	t.Run("Algorithm", func(t *testing.T) {
		var h jwk.StandardParameters
		for _, value := range []interface{}{jwa.RS256, jwa.RSA1_5} {
			if !assert.NoError(t, h.Set("alg", value), "Set for alg should succeed") {
				return
			}

			got, ok := h.Get("alg")
			if !assert.True(t, ok, "Get for alg should succeed") {
				return
			}

			if !assert.Equal(t, value.(fmt.Stringer).String(), got, "values match") {
				return
			}
		}
	})
	t.Run("KeyType", func(t *testing.T) {
		var h jwk.StandardParameters
		for _, value := range []interface{}{jwa.RSA, "RSA"} {
			if !assert.NoError(t, h.Set(jwk.KeyTypeKey, value), "Set for kty should succeed") {
				return
			}

			got, ok := h.Get(jwk.KeyTypeKey)
			if !assert.True(t, ok, "Get for kty should succeed") {
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
	})
}
