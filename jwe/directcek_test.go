package jwe_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"

	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"
	"github.com/stretchr/testify/require"
)

// injectEncryptedKey rewrites a flattened-JSON JWE serialization, replacing
// the top-level "encrypted_key" member with a non-empty base64url value.
func injectEncryptedKey(t *testing.T, serialized []byte) []byte {
	t.Helper()

	var m map[string]any
	require.NoError(t, json.Unmarshal(serialized, &m), `unmarshal flattened JWE should succeed`)

	bogus := base64.RawURLEncoding.EncodeToString([]byte("not-empty-bytes"))
	m["encrypted_key"] = bogus

	out, err := json.Marshal(m)
	require.NoError(t, err, `marshal tampered JWE should succeed`)
	return out
}

func TestDirectCEKRequiresEmptyEncryptedKey(t *testing.T) {
	t.Parallel()

	plaintext := []byte("the quick brown fox")

	t.Run("dir", func(t *testing.T) {
		t.Parallel()

		key := make([]byte, 16) // A128GCM CEK
		_, err := rand.Read(key)
		require.NoError(t, err, `rand.Read should succeed`)

		encrypted, err := jwe.Encrypt(plaintext,
			jwe.WithKey(jwa.DIRECT(), key),
			jwe.WithContentEncryption(jwa.A128GCM()),
			jwe.WithJSON(),
		)
		require.NoError(t, err, `jwe.Encrypt (dir) should succeed`)

		// Valid dir JWE (empty encrypted_key) decrypts.
		decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.DIRECT(), key))
		require.NoError(t, err, `jwe.Decrypt (dir) should succeed`)
		require.Equal(t, plaintext, decrypted)

		// dir JWE with a non-empty encrypted_key injected is rejected.
		tampered := injectEncryptedKey(t, encrypted)
		_, err = jwe.Decrypt(tampered, jwe.WithKey(jwa.DIRECT(), key))
		require.Error(t, err, `jwe.Decrypt (dir, non-empty encrypted_key) should fail`)
	})

	t.Run("ECDH-ES (bare/direct)", func(t *testing.T) {
		t.Parallel()

		privkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err, `ecdsa.GenerateKey should succeed`)

		encrypted, err := jwe.Encrypt(plaintext,
			jwe.WithKey(jwa.ECDH_ES(), &privkey.PublicKey),
			jwe.WithContentEncryption(jwa.A128GCM()),
			jwe.WithJSON(),
		)
		require.NoError(t, err, `jwe.Encrypt (ECDH-ES) should succeed`)

		// Valid bare ECDH-ES JWE (empty encrypted_key) decrypts.
		decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.ECDH_ES(), privkey))
		require.NoError(t, err, `jwe.Decrypt (ECDH-ES) should succeed`)
		require.Equal(t, plaintext, decrypted)

		// bare ECDH-ES JWE with a non-empty encrypted_key injected is rejected.
		tampered := injectEncryptedKey(t, encrypted)
		_, err = jwe.Decrypt(tampered, jwe.WithKey(jwa.ECDH_ES(), privkey))
		require.Error(t, err, `jwe.Decrypt (ECDH-ES, non-empty encrypted_key) should fail`)
	})

	t.Run("ECDH-ES+A128KW (wrapped, control)", func(t *testing.T) {
		t.Parallel()

		privkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err, `ecdsa.GenerateKey should succeed`)

		// Wrapped ECDH-ES legitimately carries a non-empty encrypted_key.
		encrypted, err := jwe.Encrypt(plaintext,
			jwe.WithKey(jwa.ECDH_ES_A128KW(), &privkey.PublicKey),
			jwe.WithContentEncryption(jwa.A128GCM()),
			jwe.WithJSON(),
		)
		require.NoError(t, err, `jwe.Encrypt (ECDH-ES+A128KW) should succeed`)

		decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.ECDH_ES_A128KW(), privkey))
		require.NoError(t, err, `jwe.Decrypt (ECDH-ES+A128KW) should succeed`)
		require.Equal(t, plaintext, decrypted)
	})
}
