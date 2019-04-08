package jwk_test

import (
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"
)

func TestHeader(t *testing.T) {
	t.Run("Roundtrip", func(t *testing.T) {
		values := map[string]interface{}{
			jwk.KeyIDKey:                  "helloworld01",
			jwk.KeyTypeKey:                jwa.RSA,
			jwk.KeyOpsKey:                 jwk.KeyOperationList{jwk.KeyOpSign},
			jwk.KeyUsageKey:               "sig",
			jwk.X509CertThumbprintKey:     "thumbprint",
			jwk.X509CertThumbprintS256Key: "thumbprint256",
			jwk.X509URLKey:                "cert1",
		}

		var h jwk.StandardHeaders
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
	t.Run("RoundtripError", func(t *testing.T) {

		type dummyStruct struct {
			dummy1 int
			dummy2 float64
		}
		dummy := &dummyStruct{1, 3.4}
		values := map[string]interface{}{
			jwk.AlgorithmKey:              dummy,
			jwk.KeyIDKey:                  dummy,
			jwk.KeyTypeKey:                dummy,
			jwk.KeyUsageKey:               dummy,
			jwk.KeyOpsKey:                 dummy,
			jwk.X509CertChainKey:          dummy,
			jwk.X509CertThumbprintKey:     dummy,
			jwk.X509CertThumbprintS256Key: dummy,
			jwk.X509URLKey:                dummy,
		}

		var h jwk.StandardHeaders
		for k, v := range values {
			err := h.Set(k, v)
			if err == nil {
				t.Fatalf("Setting %s value should have failed", k)
			}
		}
		err := h.Set("Default", dummy)
		if err != nil {
			t.Fatalf("Setting %s value failed", "default")
		}
		if h.Algorithm() != "" {
			t.Fatalf("Algorithm should be empty string")
		}
		if h.KeyID() != "" {
			t.Fatalf("KeyID should be empty string")
		}
		if h.KeyType() != "" {
			t.Fatalf("KeyType should be empty string")
		}
		if h.KeyUsage() != "" {
			t.Fatalf("KeyUsage should be empty string")
		}
		if h.KeyOps() != nil {
			t.Fatalf("KeyOps should be empty string")
		}
	})
	t.Run("ExtractMapError", func(t *testing.T) {

		type dummyStruct struct {
			dummy1 int
			dummy2 float64
		}
		dummy := &dummyStruct{1, 3.4}
		values := map[string]interface{}{
			jwk.AlgorithmKey:              dummy,
			jwk.KeyIDKey:                  dummy,
			jwk.KeyTypeKey:                dummy,
			jwk.KeyUsageKey:               dummy,
			jwk.KeyOpsKey:                 dummy,
			jwk.X509CertChainKey:          dummy,
			jwk.X509CertThumbprintKey:     dummy,
			jwk.X509CertThumbprintS256Key: dummy,
			jwk.X509URLKey:                dummy,
		}

		var h jwk.StandardHeaders
		for k, _ := range values {
			err := h.ExtractMap(values)
			if err == nil {
				t.Fatalf("Extracting %s value should have failed", k)
			}
			delete(values, k)
		}
	})

	t.Run("Algorithm", func(t *testing.T) {
		var h jwk.StandardHeaders
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
		var h jwk.StandardHeaders
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
