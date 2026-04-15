package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"
)

func TestJweDecryptRequiresExplicitKeyEncryption(t *testing.T) {
	key, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err)

	keyFile := writeSingleKeyJWK(t, key)
	jweFile := writeEncryptedJWE(t, key, jwa.RSA_OAEP(), []byte("payload"))

	app := &cli.App{
		Commands: []*cli.Command{makeJweCmd()},
	}

	err = app.Run([]string{
		"jwx",
		"jwe",
		"decrypt",
		"--key", keyFile,
		jweFile,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Required flag")
	require.Contains(t, err.Error(), "key-encryption")
}

func TestJweDecryptWithExplicitKeyEncryption(t *testing.T) {
	key, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err)

	keyFile := writeSingleKeyJWK(t, key)
	payload := []byte("payload")
	jweFile := writeEncryptedJWE(t, key, jwa.RSA_OAEP(), payload)
	outputFile := filepath.Join(t.TempDir(), "out.txt")

	app := &cli.App{
		Commands: []*cli.Command{makeJweCmd()},
	}

	err = app.Run([]string{
		"jwx",
		"jwe",
		"decrypt",
		"--key", keyFile,
		"--key-encryption", jwa.RSA_OAEP().String(),
		"--output", outputFile,
		jweFile,
	})
	require.NoError(t, err)

	got, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	require.Equal(t, payload, got)
}

func writeSingleKeyJWK(t *testing.T, key jwk.Key) string {
	t.Helper()

	buf, err := json.Marshal(key)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "key.jwk")
	require.NoError(t, os.WriteFile(path, buf, 0600))
	return path
}

func writeEncryptedJWE(t *testing.T, key jwk.Key, alg jwa.KeyEncryptionAlgorithm, payload []byte) string {
	t.Helper()

	pubkey, err := jwk.PublicKeyOf(key)
	require.NoError(t, err)

	encrypted, err := jwe.Encrypt(payload, jwe.WithKey(alg, pubkey), jwe.WithContentEncryption(jwa.A256GCM()))
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "payload.jwe")
	require.NoError(t, os.WriteFile(path, encrypted, 0600))
	return path
}
