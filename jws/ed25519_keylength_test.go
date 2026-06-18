package jws_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/require"
)

func TestSignWithMalformedEd25519Key(t *testing.T) {
	t.Parallel()

	payload := []byte("test payload")

	t.Run("short private key returns error and does not panic", func(t *testing.T) {
		t.Parallel()
		_, err := jws.Sign(payload, jws.WithKey(jwa.EdDSAEd25519(), ed25519.PrivateKey{1, 2, 3}))
		require.Error(t, err, `signing with a too-short ed25519.PrivateKey must return an error, not panic`)
	})

	t.Run("too-long private key returns error and does not panic", func(t *testing.T) {
		t.Parallel()
		key := make(ed25519.PrivateKey, ed25519.PrivateKeySize+1)
		_, err := jws.Sign(payload, jws.WithKey(jwa.EdDSAEd25519(), key))
		require.Error(t, err, `signing with a too-long ed25519.PrivateKey must return an error, not panic`)
	})

	t.Run("typed-nil private key returns error and does not panic", func(t *testing.T) {
		t.Parallel()
		_, err := jws.Sign(payload, jws.WithKey(jwa.EdDSAEd25519(), ed25519.PrivateKey(nil)))
		require.Error(t, err, `signing with a typed-nil ed25519.PrivateKey must return an error, not panic`)
	})

	t.Run("valid key still signs", func(t *testing.T) {
		t.Parallel()
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		signed, err := jws.Sign(payload, jws.WithKey(jwa.EdDSAEd25519(), priv))
		require.NoError(t, err)
		require.NotEmpty(t, signed)
	})
}
