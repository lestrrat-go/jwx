package jwk_test

import (
	"crypto/mlkem"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/require"
)

func TestAKPKey(t *testing.T) {
	t.Run("Import ML-KEM-768 EncapsulationKey", func(t *testing.T) {
		dk, err := mlkem.GenerateKey768()
		require.NoError(t, err)

		ek := dk.EncapsulationKey()

		key, err := jwk.Import[jwk.Key](ek)
		require.NoError(t, err)

		require.Equal(t, jwa.AKP(), key.KeyType())

		alg, ok := key.Algorithm()
		require.True(t, ok)
		require.Equal(t, "ML-KEM-768", alg.String())

		pub, ok := key.(jwk.AKPPublicKey)
		require.True(t, ok)

		pubBytes, ok := pub.Pub()
		require.True(t, ok)
		require.Equal(t, ek.Bytes(), pubBytes)
	})

	t.Run("Import ML-KEM-768 DecapsulationKey", func(t *testing.T) {
		dk, err := mlkem.GenerateKey768()
		require.NoError(t, err)

		key, err := jwk.Import[jwk.Key](dk)
		require.NoError(t, err)

		require.Equal(t, jwa.AKP(), key.KeyType())

		priv, ok := key.(jwk.AKPPrivateKey)
		require.True(t, ok)

		privBytes, ok := priv.Priv()
		require.True(t, ok)
		require.Len(t, privBytes, 32, "priv should be 32 bytes (d component)")

		z, ok := priv.Z()
		require.True(t, ok)
		require.Len(t, z, 32, "z should be 32 bytes")

		// Verify d || z matches the original seed
		seed := dk.Bytes()
		require.Equal(t, seed[:32], privBytes, "priv should match d")
		require.Equal(t, seed[32:], z, "z should match z")
	})

	t.Run("Export ML-KEM-768 DecapsulationKey round-trip", func(t *testing.T) {
		dk, err := mlkem.GenerateKey768()
		require.NoError(t, err)

		// Import
		key, err := jwk.Import[jwk.Key](dk)
		require.NoError(t, err)

		// Export
		exported, err := jwk.Export[*mlkem.DecapsulationKey768](key)
		require.NoError(t, err)

		// Verify same seed
		require.Equal(t, dk.Bytes(), exported.Bytes())
	})

	t.Run("Export ML-KEM-768 EncapsulationKey round-trip", func(t *testing.T) {
		dk, err := mlkem.GenerateKey768()
		require.NoError(t, err)

		ek := dk.EncapsulationKey()

		// Import
		key, err := jwk.Import[jwk.Key](ek)
		require.NoError(t, err)

		// Export
		exported, err := jwk.Export[*mlkem.EncapsulationKey768](key)
		require.NoError(t, err)

		require.Equal(t, ek.Bytes(), exported.Bytes())
	})

	t.Run("JSON round-trip with z field", func(t *testing.T) {
		dk, err := mlkem.GenerateKey768()
		require.NoError(t, err)

		key, err := jwk.Import[jwk.Key](dk)
		require.NoError(t, err)

		// Marshal
		buf, err := json.Marshal(key)
		require.NoError(t, err)

		// Verify JSON structure
		var m map[string]any
		require.NoError(t, json.Unmarshal(buf, &m))
		require.Equal(t, "AKP", m["kty"])
		require.Contains(t, m, "pub")
		require.Contains(t, m, "priv")
		require.Contains(t, m, "z")
		require.Contains(t, m, "alg")
		require.Equal(t, "ML-KEM-768", m["alg"])

		// Parse back
		parsed, err := jwk.ParseKey[jwk.Key](buf)
		require.NoError(t, err)

		// Export and verify same key
		exported, err := jwk.Export[*mlkem.DecapsulationKey768](parsed)
		require.NoError(t, err)
		require.Equal(t, dk.Bytes(), exported.Bytes())
	})

	t.Run("JSON round-trip without z field (interop)", func(t *testing.T) {
		dk, err := mlkem.GenerateKey768()
		require.NoError(t, err)

		key, err := jwk.Import[jwk.Key](dk)
		require.NoError(t, err)

		// Marshal
		buf, err := json.Marshal(key)
		require.NoError(t, err)

		// Remove the z field to simulate a JWK from another implementation
		var m map[string]any
		require.NoError(t, json.Unmarshal(buf, &m))
		delete(m, "z")
		buf, err = json.Marshal(m)
		require.NoError(t, err)

		// Parse back — should succeed, generating fresh z
		parsed, err := jwk.ParseKey[jwk.Key](buf)
		require.NoError(t, err)

		// Export — should produce a valid DecapsulationKey (with random z)
		exported, err := jwk.Export[*mlkem.DecapsulationKey768](parsed)
		require.NoError(t, err)

		// The encapsulation key should still match (ek depends only on d, not z)
		require.Equal(t, dk.EncapsulationKey().Bytes(), exported.EncapsulationKey().Bytes())
	})

	t.Run("PublicKey extraction", func(t *testing.T) {
		dk, err := mlkem.GenerateKey768()
		require.NoError(t, err)

		privKey, err := jwk.Import[jwk.Key](dk)
		require.NoError(t, err)

		pubKey, err := privKey.PublicKey()
		require.NoError(t, err)

		// Public key should not have priv or z
		require.False(t, pubKey.Has("priv"))
		require.False(t, pubKey.Has("z"))
		require.True(t, pubKey.Has("pub"))

		// Should export as EncapsulationKey
		exported, err := jwk.Export[*mlkem.EncapsulationKey768](pubKey)
		require.NoError(t, err)
		require.Equal(t, dk.EncapsulationKey().Bytes(), exported.Bytes())
	})

	t.Run("ML-KEM-1024 round-trip", func(t *testing.T) {
		dk, err := mlkem.GenerateKey1024()
		require.NoError(t, err)

		key, err := jwk.Import[jwk.Key](dk)
		require.NoError(t, err)

		alg, ok := key.Algorithm()
		require.True(t, ok)
		require.Equal(t, "ML-KEM-1024", alg.String())

		exported, err := jwk.Export[*mlkem.DecapsulationKey1024](key)
		require.NoError(t, err)
		require.Equal(t, dk.Bytes(), exported.Bytes())
	})

	t.Run("Validate", func(t *testing.T) {
		dk, err := mlkem.GenerateKey768()
		require.NoError(t, err)

		key, err := jwk.Import[jwk.Key](dk)
		require.NoError(t, err)

		require.NoError(t, key.Validate())

		pubKey, err := key.PublicKey()
		require.NoError(t, err)
		require.NoError(t, pubKey.Validate())
	})
}
