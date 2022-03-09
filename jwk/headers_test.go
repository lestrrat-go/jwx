package jwk_test

import (
	"context"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
)

func TestHeader(t *testing.T) {
	t.Parallel()

	t.Run("Roundtrip", func(t *testing.T) {
		t.Parallel()

		values := map[string]interface{}{
			jwk.KeyIDKey:                  "helloworld01",
			jwk.KeyOpsKey:                 jwk.KeyOperationList{jwk.KeyOpSign},
			jwk.KeyUsageKey:               "sig",
			jwk.X509CertThumbprintKey:     "thumbprint",
			jwk.X509CertThumbprintS256Key: "thumbprint256",
			jwk.X509URLKey:                "cert1",
			"private":                     "boofoo",
		}

		h, err := jwk.FromRaw([]byte("dummy"))
		if !assert.NoError(t, err, `jwk.New should succeed`) {
			return
		}

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

		t.Run("Private params", func(t *testing.T) {
			t.Parallel()
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
	})
	t.Run("RoundtripError", func(t *testing.T) {
		t.Parallel()
		type dummyStruct struct {
			dummy1 int
			dummy2 float64
		}
		dummy := &dummyStruct{1, 3.4}
		values := map[string]interface{}{
			jwk.AlgorithmKey:              dummy,
			jwk.KeyIDKey:                  dummy,
			jwk.KeyUsageKey:               dummy,
			jwk.KeyOpsKey:                 dummy,
			jwk.X509CertChainKey:          dummy,
			jwk.X509CertThumbprintKey:     dummy,
			jwk.X509CertThumbprintS256Key: dummy,
			jwk.X509URLKey:                dummy,
		}

		h, err := jwk.FromRaw([]byte("dummy"))
		if !assert.NoError(t, err, `jwk.New should succeed`) {
			return
		}
		for k, v := range values {
			err := h.Set(k, v)
			if err == nil {
				t.Fatalf("Setting %s value should have failed", k)
			}
		}
		if !assert.NoError(t, h.Set("Default", dummy), `Setting "Default" should succeed`) {
			return
		}
		if !assert.Empty(t, h.Algorithm().String(), "Algorithm should be empty string") {
			return
		}
		if h.KeyID() != "" {
			t.Fatalf("KeyID should be empty string")
		}
		if h.KeyUsage() != "" {
			t.Fatalf("KeyUsage should be empty string")
		}
		if h.KeyOps() != nil {
			t.Fatalf("KeyOps should be empty string")
		}
	})

	t.Run("Algorithm", func(t *testing.T) {
		t.Parallel()
		h, err := jwk.FromRaw([]byte("dummy"))
		if !assert.NoError(t, err, `jwk.New should succeed`) {
			return
		}
		for _, value := range []interface{}{jwa.RS256, jwa.RSA1_5} {
			if !assert.NoError(t, h.Set(jwk.AlgorithmKey, value), "Set for alg should succeed") {
				return
			}

			got, ok := h.Get("alg")
			if !assert.True(t, ok, "Get for alg should succeed") {
				return
			}

			if !assert.Equal(t, value, got, "values match") {
				return
			}
		}
	})
}
