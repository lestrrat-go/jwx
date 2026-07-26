package jwe_test

import (
	"encoding/base64"
	"testing"

	"github.com/lestrrat-go/jwx/v3/internal/json"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/stretchr/testify/require"
)

func TestEncryptWithAuthenticateData(t *testing.T) {
	const payload = "encrypted payload"
	aad := []byte("external aad")
	key1 := []byte("01234567890123456789012345678901")
	key2 := []byte("abcdefghijklmnopqrstuvwxyz123456")

	encrypted, err := jwe.Encrypt(
		[]byte(payload),
		jwe.WithJSON(),
		jwe.WithAuthenticateData(aad),
		jwe.WithKey(jwa.A256KW(), key1),
		jwe.WithKey(jwa.A256KW(), key2),
	)
	require.NoError(t, err)

	var wire struct {
		AAD string `json:"aad"`
	}
	require.NoError(t, json.Unmarshal(encrypted, &wire))
	require.Equal(t, base64.RawURLEncoding.EncodeToString(aad), wire.AAD)

	msg, err := jwe.Parse(encrypted)
	require.NoError(t, err)
	require.Equal(t, aad, msg.AuthenticatedData())

	for name, key := range map[string][]byte{"first recipient": key1, "second recipient": key2} {
		t.Run(name, func(t *testing.T) {
			decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.A256KW(), key))
			require.NoError(t, err)
			require.Equal(t, []byte(payload), decrypted)
		})
	}
}

func TestEncryptWithAuthenticateDataRejectsCompact(t *testing.T) {
	_, err := jwe.Encrypt(
		[]byte("encrypted payload"),
		jwe.WithAuthenticateData([]byte("external aad")),
		jwe.WithKey(jwa.A256KW(), []byte("01234567890123456789012345678901")),
	)
	require.ErrorContains(t, err, `cannot use compact serialization with external authenticated data`)
}
