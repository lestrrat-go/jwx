package jwk_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"
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

		h, err := jwk.Import([]byte("dummy"))
		require.NoError(t, err, `jwk.New should succeed`)

		for k, v := range values {
			require.NoError(t, h.Set(k, v), "Set works for '%s'", k)

			var got interface{}
			require.NoError(t, h.Get(k, &got), "Get works for '%s'", k)
			require.Equal(t, v, got, "values match '%s'", k)
			require.NoError(t, h.Set(k, v), "Set works for '%s'", k)
		}

		t.Run("Private params", func(t *testing.T) {
			t.Parallel()
			var v string
			require.NoError(t, h.Get(`private`, &v), `h.Get should succeed`)
			require.Equal(t, v, "boofoo", "value for 'private' should match")
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

		h, err := jwk.Import([]byte("dummy"))
		require.NoError(t, err, `jwk.New should succeed`)
		for k, v := range values {
			err := h.Set(k, v)
			if err == nil {
				t.Fatalf("Setting %s value should have failed", k)
			}
		}
		require.NoError(t, h.Set("Default", dummy), `Setting "Default" should succeed`)
		require.Nil(t, h.Algorithm(), "Algorithm should be nil")
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
		h, err := jwk.Import([]byte("dummy"))
		require.NoError(t, err, `jwk.New should succeed`)
		for _, value := range []interface{}{jwa.RS256(), jwa.RSA1_5()} {
			require.NoError(t, h.Set(jwk.AlgorithmKey, value), "Set for alg should succeed")

			var got jwa.KeyAlgorithm
			require.NoError(t, h.Get("alg", &got), "Get for alg should succeed")
			require.Equal(t, value, got, "values match")
		}
	})
}
