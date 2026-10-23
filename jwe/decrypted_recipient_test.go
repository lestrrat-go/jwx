package jwe_test

import (
	"bytes"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"
	"github.com/stretchr/testify/require"
)

func TestDecryptWithDecryptedRecipient(t *testing.T) {
	t.Parallel()

	plaintext := []byte(`Lorem ipsum`)
	keyA := bytes.Repeat([]byte{0x41}, 16)
	keyB := bytes.Repeat([]byte{0x42}, 16)

	recipientHeaders := func(t *testing.T, kid string) jwe.Headers {
		t.Helper()
		hdrs := jwe.NewHeaders()
		require.NoError(t, hdrs.Set(jwe.KeyIDKey, kid), `hdrs.Set should succeed`)
		return hdrs
	}

	encryptForBoth := func(t *testing.T) []byte {
		t.Helper()
		encrypted, err := jwe.Encrypt(plaintext,
			jwe.WithJSON(),
			jwe.WithKey(jwa.A128KW(), keyA, jwe.WithPerRecipientHeaders(recipientHeaders(t, "a"))),
			jwe.WithKey(jwa.A128KW(), keyB, jwe.WithPerRecipientHeaders(recipientHeaders(t, "b"))),
		)
		require.NoError(t, err, `jwe.Encrypt should succeed`)
		return encrypted
	}

	kidOf := func(t *testing.T, r jwe.Recipient) string {
		t.Helper()
		kid, ok := r.Headers().KeyID()
		require.True(t, ok, `recipient should carry a key ID`)
		return kid
	}

	t.Run("second recipient decrypts", func(t *testing.T) {
		t.Parallel()

		var used jwe.Recipient
		msg := jwe.NewMessage()
		decrypted, err := jwe.Decrypt(encryptForBoth(t),
			jwe.WithKey(jwa.A128KW(), keyB),
			jwe.WithMessage(msg),
			jwe.WithDecryptedRecipient(&used),
		)
		require.NoError(t, err, `jwe.Decrypt should succeed`)
		require.Equal(t, plaintext, decrypted)
		require.NotNil(t, used, `WithDecryptedRecipient should be set`)
		require.Equal(t, "b", kidOf(t, used))
		require.Same(t, msg.Recipients()[1], used, `recipient should be an entry of the message`)
	})

	t.Run("first recipient decrypts", func(t *testing.T) {
		t.Parallel()

		var used jwe.Recipient
		msg := jwe.NewMessage()
		_, err := jwe.Decrypt(encryptForBoth(t),
			jwe.WithKey(jwa.A128KW(), keyA),
			jwe.WithMessage(msg),
			jwe.WithDecryptedRecipient(&used),
		)
		require.NoError(t, err, `jwe.Decrypt should succeed`)
		require.Equal(t, "a", kidOf(t, used))
		require.Same(t, msg.Recipients()[0], used)
	})

	t.Run("flattened JSON", func(t *testing.T) {
		t.Parallel()

		encrypted, err := jwe.Encrypt(plaintext,
			jwe.WithJSON(),
			jwe.WithKey(jwa.A128KW(), keyA, jwe.WithPerRecipientHeaders(recipientHeaders(t, "a"))),
		)
		require.NoError(t, err, `jwe.Encrypt should succeed`)

		var used jwe.Recipient
		msg := jwe.NewMessage()
		_, err = jwe.Decrypt(encrypted,
			jwe.WithKey(jwa.A128KW(), keyA),
			jwe.WithMessage(msg),
			jwe.WithDecryptedRecipient(&used),
		)
		require.NoError(t, err, `jwe.Decrypt should succeed`)
		require.NotNil(t, used, `WithDecryptedRecipient should be set`)
		require.Len(t, msg.Recipients(), 1, `a flattened message has one recipient`)
		require.Same(t, msg.Recipients()[0], used)
		require.NotEmpty(t, used.EncryptedKey(), `recipient should carry the encrypted key that was unwrapped`)
	})

	t.Run("compact", func(t *testing.T) {
		t.Parallel()

		encrypted, err := jwe.Encrypt(plaintext, jwe.WithKey(jwa.A128KW(), keyA))
		require.NoError(t, err, `jwe.Encrypt should succeed`)

		var used jwe.Recipient
		_, err = jwe.Decrypt(encrypted,
			jwe.WithKey(jwa.A128KW(), keyA),
			jwe.WithDecryptedRecipient(&used),
		)
		require.NoError(t, err, `jwe.Decrypt should succeed`)
		require.NotNil(t, used, `WithDecryptedRecipient should be set`)
		alg, ok := used.Headers().Algorithm()
		require.True(t, ok, `recipient built from the protected header should carry "alg"`)
		require.Equal(t, jwa.A128KW(), alg)
	})

	t.Run("failed decryption leaves the variable untouched", func(t *testing.T) {
		t.Parallel()

		var used jwe.Recipient
		_, err := jwe.Decrypt(encryptForBoth(t),
			jwe.WithKey(jwa.A128KW(), bytes.Repeat([]byte{0x43}, 16)),
			jwe.WithDecryptedRecipient(&used),
		)
		require.Error(t, err, `jwe.Decrypt should fail`)
		require.Nil(t, used, `WithDecryptedRecipient should not be set on failure`)
	})
}
