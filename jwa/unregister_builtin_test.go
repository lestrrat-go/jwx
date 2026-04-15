package jwa_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/stretchr/testify/require"
)

// TestUnregisterBuiltinIgnored asserts that the Unregister* family refuses to
// remove built-in algorithms, as documented on each Unregister* function.
// Regression test for a bug where the builtin guard map was declared but never
// populated by the generator, so Unregister would silently delete built-ins.
func TestUnregisterBuiltinIgnored(t *testing.T) {
	t.Run("SignatureAlgorithm", func(t *testing.T) {
		jwa.UnregisterSignatureAlgorithm(jwa.RS256())
		_, ok := jwa.LookupSignatureAlgorithm("RS256")
		require.True(t, ok, "RS256 must survive Unregister")
	})
	t.Run("KeyEncryptionAlgorithm", func(t *testing.T) {
		jwa.UnregisterKeyEncryptionAlgorithm(jwa.RSA_OAEP())
		_, ok := jwa.LookupKeyEncryptionAlgorithm("RSA-OAEP")
		require.True(t, ok, "RSA-OAEP must survive Unregister")
	})
	t.Run("ContentEncryptionAlgorithm", func(t *testing.T) {
		jwa.UnregisterContentEncryptionAlgorithm(jwa.A128GCM())
		_, ok := jwa.LookupContentEncryptionAlgorithm("A128GCM")
		require.True(t, ok, "A128GCM must survive Unregister")
	})
	t.Run("EllipticCurveAlgorithm", func(t *testing.T) {
		jwa.UnregisterEllipticCurveAlgorithm(jwa.P256())
		_, ok := jwa.LookupEllipticCurveAlgorithm("P-256")
		require.True(t, ok, "P-256 must survive Unregister")
	})
	t.Run("KeyType", func(t *testing.T) {
		jwa.UnregisterKeyType(jwa.RSA())
		_, ok := jwa.LookupKeyType("RSA")
		require.True(t, ok, "RSA must survive Unregister")
	})
	t.Run("CompressionAlgorithm", func(t *testing.T) {
		jwa.UnregisterCompressionAlgorithm(jwa.Deflate())
		_, ok := jwa.LookupCompressionAlgorithm("DEF")
		require.True(t, ok, "DEF must survive Unregister")
	})
}
