//go:build go1.27

package jwa_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/stretchr/testify/require"
)

// Lookup, unmarshal, stringification, and the symmetric flag are covered by
// signature_go127_gen_test.go. What is left here is the behavior the generated
// tests skip for build-constrained algorithms, plus the builtin guarantee.
func TestMLDSASignatureAlgorithms(t *testing.T) {
	t.Parallel()

	algs := []jwa.SignatureAlgorithm{jwa.MLDSA44(), jwa.MLDSA65(), jwa.MLDSA87()}

	t.Run("not deprecated", func(t *testing.T) {
		t.Parallel()
		for _, alg := range algs {
			require.False(t, alg.IsDeprecated(), "%s must not be deprecated", alg)
		}
	})

	// The generated whole-list check skips these names, since whether they are
	// present depends on the toolchain.
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
	// unregister ML-DSA out from under the signer and verifier registered for
	// it.
	t.Run("unregister is refused", func(t *testing.T) {
		t.Parallel()
		jwa.UnregisterSignatureAlgorithm(jwa.MLDSA44())
		_, ok := jwa.LookupSignatureAlgorithm("ML-DSA-44")
		require.True(t, ok, "ML-DSA-44 must survive an unregister attempt")
	})
}
