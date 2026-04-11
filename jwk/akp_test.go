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

		// Verify d matches the original seed's first 32 bytes
		seed := dk.Bytes()
		require.Equal(t, seed[:32], privBytes, "priv should match d")
	})

	t.Run("Export ML-KEM-768 DecapsulationKey", func(t *testing.T) {
		dk, err := mlkem.GenerateKey768()
		require.NoError(t, err)

		// Import
		key, err := jwk.Import[jwk.Key](dk)
		require.NoError(t, err)

		// Export — z is randomly generated, so the seed will differ,
		// but the encapsulation key (derived from d alone) must match.
		exported, err := jwk.Export[*mlkem.DecapsulationKey768](key)
		require.NoError(t, err)

		require.Equal(t, dk.EncapsulationKey().Bytes(), exported.EncapsulationKey().Bytes())
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

	t.Run("JSON round-trip", func(t *testing.T) {
		dk, err := mlkem.GenerateKey768()
		require.NoError(t, err)

		key, err := jwk.Import[jwk.Key](dk)
		require.NoError(t, err)

		// Marshal
		buf, err := json.Marshal(key)
		require.NoError(t, err)

		// Verify JSON structure — no z field
		var m map[string]any
		require.NoError(t, json.Unmarshal(buf, &m))
		require.Equal(t, "AKP", m["kty"])
		require.Contains(t, m, "pub")
		require.Contains(t, m, "priv")
		require.NotContains(t, m, "z")
		require.Contains(t, m, "alg")
		require.Equal(t, "ML-KEM-768", m["alg"])

		// Parse back
		parsed, err := jwk.ParseKey[jwk.Key](buf)
		require.NoError(t, err)

		// Export and verify encapsulation key matches (d is preserved)
		exported, err := jwk.Export[*mlkem.DecapsulationKey768](parsed)
		require.NoError(t, err)
		require.Equal(t, dk.EncapsulationKey().Bytes(), exported.EncapsulationKey().Bytes())
	})

	t.Run("PublicKey extraction", func(t *testing.T) {
		dk, err := mlkem.GenerateKey768()
		require.NoError(t, err)

		privKey, err := jwk.Import[jwk.Key](dk)
		require.NoError(t, err)

		pubKey, err := privKey.PublicKey()
		require.NoError(t, err)

		// Public key should not have priv
		require.False(t, pubKey.Has("priv"))
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
		require.Equal(t, dk.EncapsulationKey().Bytes(), exported.EncapsulationKey().Bytes())
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
