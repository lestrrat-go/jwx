package jwe_test

import (
	"crypto/mlkem"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/stretchr/testify/require"
)

func TestMLKEM(t *testing.T) {
	payload := []byte("Hello, post-quantum world!")

	t.Run("ML-KEM-768 direct", func(t *testing.T) {
		dk, err := mlkem.GenerateKey768()
		require.NoError(t, err)

		ek := dk.EncapsulationKey()

		encrypted, err := jwe.Encrypt(payload,
			jwe.WithKey(jwa.ML_KEM_768(), ek),
			jwe.WithContentEncryption(jwa.A256GCM()),
		)
		require.NoError(t, err, "Encrypt should succeed")

		decrypted, err := jwe.Decrypt(encrypted,
			jwe.WithKey(jwa.ML_KEM_768(), dk),
		)
		require.NoError(t, err, "Decrypt should succeed")
		require.Equal(t, payload, decrypted)
	})

	t.Run("ML-KEM-1024 direct", func(t *testing.T) {
		dk, err := mlkem.GenerateKey1024()
		require.NoError(t, err)

		ek := dk.EncapsulationKey()

		encrypted, err := jwe.Encrypt(payload,
			jwe.WithKey(jwa.ML_KEM_1024(), ek),
			jwe.WithContentEncryption(jwa.A256GCM()),
		)
		require.NoError(t, err, "Encrypt should succeed")

		decrypted, err := jwe.Decrypt(encrypted,
			jwe.WithKey(jwa.ML_KEM_1024(), dk),
		)
		require.NoError(t, err, "Decrypt should succeed")
		require.Equal(t, payload, decrypted)
	})

	t.Run("ML-KEM-768+A192KW key wrap", func(t *testing.T) {
		dk, err := mlkem.GenerateKey768()
		require.NoError(t, err)

		ek := dk.EncapsulationKey()

		encrypted, err := jwe.Encrypt(payload,
			jwe.WithKey(jwa.ML_KEM_768_A192KW(), ek),
			jwe.WithContentEncryption(jwa.A256GCM()),
		)
		require.NoError(t, err, "Encrypt should succeed")

		decrypted, err := jwe.Decrypt(encrypted,
			jwe.WithKey(jwa.ML_KEM_768_A192KW(), dk),
		)
		require.NoError(t, err, "Decrypt should succeed")
		require.Equal(t, payload, decrypted)
	})

	t.Run("ML-KEM-1024+A256KW key wrap", func(t *testing.T) {
		dk, err := mlkem.GenerateKey1024()
		require.NoError(t, err)

		ek := dk.EncapsulationKey()

		encrypted, err := jwe.Encrypt(payload,
			jwe.WithKey(jwa.ML_KEM_1024_A256KW(), ek),
			jwe.WithContentEncryption(jwa.A256GCM()),
		)
		require.NoError(t, err, "Encrypt should succeed")

		decrypted, err := jwe.Decrypt(encrypted,
			jwe.WithKey(jwa.ML_KEM_1024_A256KW(), dk),
		)
		require.NoError(t, err, "Decrypt should succeed")
		require.Equal(t, payload, decrypted)
	})

	t.Run("ML-KEM-768 key mismatch with ML-KEM-1024", func(t *testing.T) {
		dk768, err := mlkem.GenerateKey768()
		require.NoError(t, err)

		dk1024, err := mlkem.GenerateKey1024()
		require.NoError(t, err)

		// Encrypt with 768, try to decrypt with 1024 — should fail
		encrypted, err := jwe.Encrypt(payload,
			jwe.WithKey(jwa.ML_KEM_768(), dk768.EncapsulationKey()),
			jwe.WithContentEncryption(jwa.A256GCM()),
		)
		require.NoError(t, err)

		_, err = jwe.Decrypt(encrypted,
			jwe.WithKey(jwa.ML_KEM_768(), dk1024),
		)
		require.Error(t, err, "Decrypt with wrong key type should fail")
	})

	t.Run("ML-KEM with different content encryption algorithms", func(t *testing.T) {
		dk, err := mlkem.GenerateKey768()
		require.NoError(t, err)

		for _, calg := range []jwa.ContentEncryptionAlgorithm{
			jwa.A128GCM(),
			jwa.A192GCM(),
			jwa.A256GCM(),
			jwa.A128CBC_HS256(),
			jwa.A256CBC_HS512(),
		} {
			t.Run(calg.String(), func(t *testing.T) {
				encrypted, err := jwe.Encrypt(payload,
					jwe.WithKey(jwa.ML_KEM_768(), dk.EncapsulationKey()),
					jwe.WithContentEncryption(calg),
				)
				require.NoError(t, err, "Encrypt should succeed")

				decrypted, err := jwe.Decrypt(encrypted,
					jwe.WithKey(jwa.ML_KEM_768(), dk),
				)
				require.NoError(t, err, "Decrypt should succeed")
				require.Equal(t, payload, decrypted)
			})
		}
	})
}
