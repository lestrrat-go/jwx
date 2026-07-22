package jwe_test

import (
	"context"
	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/lestrrat-go/jwx/v4/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/require"
)

// An unknown "kty" entry parses (in retain mode) into a jwk.UnsupportedKey
// placeholder rather than failing the whole set. These tests pin the
// crypto-isolation invariant: such a placeholder must NEVER reach encryption
// or decryption key material through any of jwe's key-provider paths
// (jwe.WithKeySet, jwe.WithKey, or a custom jwe.WithKeyProvider).
const unsupportedKeyEntry = `{"kty":"FUTURE","kid":"future-1"}`

// parseSetWithPlaceholder builds a JWK set JSON from the given usable key JSON
// plus one unknown-kty entry, parses it in retain mode, and returns the parsed
// set together with the retained placeholder.
func parseSetWithPlaceholder(t *testing.T, usableKeyJSON []byte) (jwk.Set, jwk.UnsupportedKey) {
	t.Helper()

	setJSON := []byte(`{"keys":[` + string(usableKeyJSON) + `,` + unsupportedKeyEntry + `]}`)
	set, err := jwk.Parse(setJSON, jwk.WithStrictKeySetParsing(false))
	require.NoError(t, err, `jwk.Parse in retain mode should succeed`)

	var placeholder jwk.UnsupportedKey
	for i := range set.Len() {
		key, ok := set.Key(i)
		require.True(t, ok, `set.Key(%d) should be present`, i)
		if uk, ok := key.(jwk.UnsupportedKey); ok {
			placeholder = uk
		}
	}
	require.NotNil(t, placeholder, `set should retain the unknown entry as an UnsupportedKey placeholder`)
	require.True(t, jwk.IsUnsupportedKey(placeholder), `placeholder should report IsUnsupportedKey`)
	require.Error(t, placeholder.Reason(), `placeholder should retain its parse error`)
	return set, placeholder
}

func TestUnsupportedKeyRejectedAcrossKeyPaths(t *testing.T) {
	t.Parallel()

	rawPriv, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err, `generating RSA key should succeed`)

	// Private JWK is what the decrypting set carries (RSA-OAEP unwrap needs
	// the private key); marshal it so it can be embedded in the set JSON.
	privJWK, err := jwk.Import[jwk.Key](rawPriv)
	require.NoError(t, err, `importing RSA private key should succeed`)
	require.NoError(t, privJWK.Set(jwk.AlgorithmKey, jwa.RSA_OAEP()))
	require.NoError(t, privJWK.Set(jwk.KeyIDKey, "usable"))
	usableKeyJSON, err := json.Marshal(privJWK)
	require.NoError(t, err, `marshaling usable JWK should succeed`)

	// Encrypt a payload to the usable key so every path below decrypts a
	// genuine ciphertext.
	pubJWK, err := jwk.Import[jwk.Key](rawPriv.PublicKey)
	require.NoError(t, err, `importing RSA public key should succeed`)
	require.NoError(t, pubJWK.Set(jwk.KeyIDKey, "usable"))

	payload := []byte("super secret encrypted message")
	ciphertext, err := jwe.Encrypt(payload, jwe.WithKey(jwa.RSA_OAEP(), pubJWK))
	require.NoError(t, err, `jwe.Encrypt to the usable key should succeed`)

	t.Run("WithKeySet decrypts via the usable key and never the placeholder", func(t *testing.T) {
		t.Parallel()
		set, _ := parseSetWithPlaceholder(t, usableKeyJSON)

		var used any
		plaintext, err := jwe.Decrypt(ciphertext,
			jwe.WithKeySet(set, jwe.WithRequireKid(false)),
			jwe.WithKeyUsed(&used),
		)
		require.NoError(t, err, `jwe.Decrypt should succeed via the usable key`)
		require.Equal(t, payload, plaintext, `decrypted plaintext should match`)

		usedKey, ok := used.(jwk.Key)
		require.True(t, ok, `key used should be a jwk.Key`)
		require.False(t, jwk.IsUnsupportedKey(usedKey), `the placeholder must never be the used key`)
	})

	t.Run("WithKeySet containing only the placeholder fails with no plaintext", func(t *testing.T) {
		t.Parallel()
		setJSON := []byte(`{"keys":[` + unsupportedKeyEntry + `]}`)
		set, err := jwk.Parse(setJSON, jwk.WithStrictKeySetParsing(false))
		require.NoError(t, err, `jwk.Parse in retain mode should succeed`)
		key, ok := set.Key(0)
		require.True(t, ok, `set should have one entry`)
		placeholder, ok := key.(jwk.UnsupportedKey)
		require.True(t, ok, `the only entry should be the placeholder`)

		plaintext, err := jwe.Decrypt(ciphertext, jwe.WithKeySet(set, jwe.WithRequireKid(false)))
		require.Error(t, err, `jwe.Decrypt must fail when the only key is a placeholder`)
		require.Nil(t, plaintext, `no plaintext must be produced`)
		require.ErrorIs(t, err, placeholder.Reason(), `error should surface the placeholder's unsupported reason`)
	})

	t.Run("direct WithKey with the placeholder fails for Decrypt and Encrypt", func(t *testing.T) {
		t.Parallel()
		_, placeholder := parseSetWithPlaceholder(t, usableKeyJSON)

		plaintext, err := jwe.Decrypt(ciphertext, jwe.WithKey(jwa.RSA_OAEP(), placeholder))
		require.Error(t, err, `jwe.Decrypt with a placeholder must fail`)
		require.Nil(t, plaintext, `no plaintext must be produced`)
		require.ErrorIs(t, err, placeholder.Reason(), `Decrypt error should surface the unsupported reason`)

		encrypted, err := jwe.Encrypt(payload, jwe.WithKey(jwa.RSA_OAEP(), placeholder))
		require.Error(t, err, `jwe.Encrypt with a placeholder must fail`)
		require.Nil(t, encrypted, `no ciphertext must be produced`)
		require.ErrorIs(t, err, placeholder.Reason(), `Encrypt error should surface the unsupported reason`)
	})

	t.Run("custom KeyProvider that sinks the placeholder fails with no plaintext", func(t *testing.T) {
		t.Parallel()
		_, placeholder := parseSetWithPlaceholder(t, usableKeyJSON)

		provider := jwe.KeyProviderFunc(func(_ context.Context, sink jwe.KeySink, _ jwe.Recipient, _ *jwe.Message) error {
			sink.Key(jwa.RSA_OAEP(), placeholder)
			return nil
		})

		plaintext, err := jwe.Decrypt(ciphertext, jwe.WithKeyProvider(provider))
		require.Error(t, err, `jwe.Decrypt via a placeholder-sinking provider must fail`)
		require.Nil(t, plaintext, `no plaintext must be produced`)
		require.ErrorIs(t, err, placeholder.Reason(), `error should surface the unsupported reason`)
	})
}
