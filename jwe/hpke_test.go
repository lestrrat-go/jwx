package jwe_test

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/require"
)

// hpkeAlgKey pairs an HPKE-KE algorithm with a function that generates the
// appropriate key pair (public key for encrypt, private key for decrypt).
type hpkeAlgKey struct {
	alg     jwa.KeyEncryptionAlgorithm
	genPriv func(t *testing.T) *ecdh.PrivateKey
}

func hpkeTestCases() []hpkeAlgKey {
	return []hpkeAlgKey{
		{jwa.HPKE_0_KE(), genP256},
		{jwa.HPKE_1_KE(), genP384},
		{jwa.HPKE_2_KE(), genP521},
		{jwa.HPKE_3_KE(), genX25519},
		{jwa.HPKE_4_KE(), genX25519},
		{jwa.HPKE_7_KE(), genP256},
	}
}

func genP256(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	return k
}

func genP384(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.P384().GenerateKey(rand.Reader)
	require.NoError(t, err)
	return k
}

func genP521(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.P521().GenerateKey(rand.Reader)
	require.NoError(t, err)
	return k
}

func genX25519(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	return k
}

func TestHPKE(t *testing.T) {
	payload := []byte("Hello, HPKE world!")

	t.Run("round-trip per algorithm", func(t *testing.T) {
		for _, tc := range hpkeTestCases() {
			t.Run(tc.alg.String(), func(t *testing.T) {
				priv := tc.genPriv(t)
				pub := priv.PublicKey()

				encrypted, err := jwe.Encrypt(payload,
					jwe.WithKey(tc.alg, pub),
					jwe.WithContentEncryption(jwa.A256GCM()),
				)
				require.NoError(t, err, "Encrypt should succeed")

				decrypted, err := jwe.Decrypt(encrypted,
					jwe.WithKey(tc.alg, priv),
				)
				require.NoError(t, err, "Decrypt should succeed")
				require.Equal(t, payload, decrypted)
			})
		}
	})

	t.Run("with different content encryption algorithms", func(t *testing.T) {
		calgs := []jwa.ContentEncryptionAlgorithm{
			jwa.A128GCM(),
			jwa.A192GCM(),
			jwa.A256GCM(),
			jwa.A128CBC_HS256(),
			jwa.A256CBC_HS512(),
		}

		// Use HPKE-0-KE (P-256) as representative
		priv := genP256(t)
		pub := priv.PublicKey()

		for _, calg := range calgs {
			t.Run(calg.String(), func(t *testing.T) {
				encrypted, err := jwe.Encrypt(payload,
					jwe.WithKey(jwa.HPKE_0_KE(), pub),
					jwe.WithContentEncryption(calg),
				)
				require.NoError(t, err, "Encrypt should succeed")

				decrypted, err := jwe.Decrypt(encrypted,
					jwe.WithKey(jwa.HPKE_0_KE(), priv),
				)
				require.NoError(t, err, "Decrypt should succeed")
				require.Equal(t, payload, decrypted)
			})
		}
	})

	t.Run("compact serialization round-trip", func(t *testing.T) {
		priv := genP256(t)
		pub := priv.PublicKey()

		encrypted, err := jwe.Encrypt(payload,
			jwe.WithKey(jwa.HPKE_0_KE(), pub),
			jwe.WithContentEncryption(jwa.A128GCM()),
		)
		require.NoError(t, err)

		// Parse the compact serialization
		msg, err := jwe.Parse(encrypted)
		require.NoError(t, err, "Parse should succeed")

		// Verify algorithm in protected headers
		alg, ok := msg.ProtectedHeaders().Algorithm()
		require.True(t, ok)
		require.Equal(t, jwa.HPKE_0_KE(), alg)

		// Decrypt from parsed message
		decrypted, err := jwe.Decrypt(encrypted,
			jwe.WithKey(jwa.HPKE_0_KE(), priv),
		)
		require.NoError(t, err)
		require.Equal(t, payload, decrypted)
	})

	t.Run("ek header is present", func(t *testing.T) {
		priv := genP256(t)
		pub := priv.PublicKey()

		encrypted, err := jwe.Encrypt(payload,
			jwe.WithKey(jwa.HPKE_0_KE(), pub),
			jwe.WithContentEncryption(jwa.A128GCM()),
		)
		require.NoError(t, err)

		msg, err := jwe.Parse(encrypted)
		require.NoError(t, err)

		// The "ek" (encapsulated key) should be present in recipient headers
		// or merged headers
		recipients := msg.Recipients()
		require.Len(t, recipients, 1)

		// Check that encapsulated key is set somewhere in the headers
		hdr := recipients[0].Headers()
		ek, ok := hdr.EncapsulatedKey()
		require.True(t, ok, "encapsulated key should be present in recipient headers")
		require.NotEmpty(t, ek, "encapsulated key should not be empty")
	})

	t.Run("wrong key type fails", func(t *testing.T) {
		// Encrypt with P-256 (HPKE-0-KE), try to decrypt with X25519 key
		privP256 := genP256(t)
		pubP256 := privP256.PublicKey()

		encrypted, err := jwe.Encrypt(payload,
			jwe.WithKey(jwa.HPKE_0_KE(), pubP256),
			jwe.WithContentEncryption(jwa.A256GCM()),
		)
		require.NoError(t, err)

		privX25519 := genX25519(t)
		_, err = jwe.Decrypt(encrypted,
			jwe.WithKey(jwa.HPKE_0_KE(), privX25519),
		)
		require.Error(t, err, "Decrypt with wrong key curve should fail")
	})

	t.Run("wrong algorithm for key fails decrypt", func(t *testing.T) {
		// Encrypt with HPKE-0-KE (P-256), try to decrypt with HPKE-3-KE (X25519)
		privP256 := genP256(t)
		pubP256 := privP256.PublicKey()

		encrypted, err := jwe.Encrypt(payload,
			jwe.WithKey(jwa.HPKE_0_KE(), pubP256),
			jwe.WithContentEncryption(jwa.A256GCM()),
		)
		require.NoError(t, err)

		privX25519 := genX25519(t)
		_, err = jwe.Decrypt(encrypted,
			jwe.WithKey(jwa.HPKE_3_KE(), privX25519),
		)
		require.Error(t, err, "Decrypt with wrong algorithm should fail")
	})

	t.Run("ecdsa key works", func(t *testing.T) {
		// HPKE-0-KE uses P-256; test that *ecdsa.PrivateKey also works
		ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		encrypted, err := jwe.Encrypt(payload,
			jwe.WithKey(jwa.HPKE_0_KE(), &ecdsaPriv.PublicKey),
			jwe.WithContentEncryption(jwa.A256GCM()),
		)
		require.NoError(t, err, "Encrypt with *ecdsa.PublicKey should succeed")

		decrypted, err := jwe.Decrypt(encrypted,
			jwe.WithKey(jwa.HPKE_0_KE(), ecdsaPriv),
		)
		require.NoError(t, err, "Decrypt with *ecdsa.PrivateKey should succeed")
		require.Equal(t, payload, decrypted)
	})

	t.Run("jwk.Key integration", func(t *testing.T) {
		priv := genP256(t)
		pub := priv.PublicKey()

		// Import into JWK
		privJWK, err := jwk.Import[jwk.Key](priv)
		require.NoError(t, err)

		pubJWK, err := jwk.Import[jwk.Key](pub)
		require.NoError(t, err)

		encrypted, err := jwe.Encrypt(payload,
			jwe.WithKey(jwa.HPKE_0_KE(), pubJWK),
			jwe.WithContentEncryption(jwa.A256GCM()),
		)
		require.NoError(t, err, "Encrypt with jwk.Key should succeed")

		decrypted, err := jwe.Decrypt(encrypted,
			jwe.WithKey(jwa.HPKE_0_KE(), privJWK),
		)
		require.NoError(t, err, "Decrypt with jwk.Key should succeed")
		require.Equal(t, payload, decrypted)
	})
}
