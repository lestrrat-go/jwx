//go:build go1.27

package jwa_test

import (
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/stretchr/testify/require"
)

func TestMLDSASignatureAlgorithms(t *testing.T) {
	t.Parallel()

	t.Run("names", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "ML-DSA-44", jwa.MLDSA44().String())
		require.Equal(t, "ML-DSA-65", jwa.MLDSA65().String())
		require.Equal(t, "ML-DSA-87", jwa.MLDSA87().String())
	})

	t.Run("registered for lookup", func(t *testing.T) {
		t.Parallel()
		for _, name := range []string{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"} {
			alg, ok := jwa.LookupSignatureAlgorithm(name)
			require.True(t, ok, "%s must be registered", name)
			require.Equal(t, name, alg.String())
		}
	})

	t.Run("asymmetric and not deprecated", func(t *testing.T) {
		t.Parallel()
		for _, alg := range []jwa.SignatureAlgorithm{jwa.MLDSA44(), jwa.MLDSA65(), jwa.MLDSA87()} {
			require.False(t, alg.IsSymmetric(), "%s must not be symmetric", alg)
			require.False(t, alg.IsDeprecated(), "%s must not be deprecated", alg)
		}
	})

	t.Run("unmarshal from JSON", func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		require.NoError(t, json.Unmarshal([]byte(`"ML-DSA-65"`), &dst))
		require.Equal(t, jwa.MLDSA65(), dst)
	})

	t.Run("listed among signature algorithms", func(t *testing.T) {
		t.Parallel()
		var found int
		for _, alg := range jwa.SignatureAlgorithms() {
			switch alg.String() {
			case "ML-DSA-44", "ML-DSA-65", "ML-DSA-87":
				found++
			}
		}
		require.Equal(t, 3, found, "all three ML-DSA algorithms must be listed")
	})

	// Built-in algorithms are protected from removal, so an extension cannot
	// unregister ML-DSA out from under the signer and verifier that core
	// registered for it.
	t.Run("unregister is refused", func(t *testing.T) {
		t.Parallel()
		jwa.UnregisterSignatureAlgorithm(jwa.MLDSA44())
		_, ok := jwa.LookupSignatureAlgorithm("ML-DSA-44")
		require.True(t, ok, "ML-DSA-44 must survive an unregister attempt")
	})
}
