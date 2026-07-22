package jwe_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v3/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/stretchr/testify/require"
)

// The crypto-isolation invariant under test: a jwk.UnsupportedKey
// placeholder (retained for an unparseable JWK Set entry via
// jwk.WithStrictKeySetParsing(false)) must NEVER reach encryption or
// decryption key material in the jwe package. Each test below fails if a
// future change lets the placeholder through — either the operation
// errors, or it yields no plaintext.

// unknownEntryJSON is a JWK Set entry whose key type is not understood by
// this build. Parsed with retention it becomes a jwk.UnsupportedKey
// placeholder. The kty and kid are distinctive so error messages can be
// checked for them.
const unknownEntryJSON = `{"kty":"FUTURE","kid":"future1","x":"dGVzdA"}`

// parseUnsupportedPlaceholder parses a JWK Set holding a single
// unparseable entry with retention enabled and returns the resulting
// placeholder key.
func parseUnsupportedPlaceholder(t *testing.T) jwk.Key {
	t.Helper()
	set, err := jwk.Parse([]byte(`{"keys":[`+unknownEntryJSON+`]}`), jwk.WithStrictKeySetParsing(false))
	require.NoError(t, err)
	key, ok := set.LookupKeyID("future1")
	require.True(t, ok, "placeholder should be discoverable by kid")
	require.True(t, jwk.IsUnsupportedKey(key), "retained entry must be an UnsupportedKey placeholder")
	return key
}

// encryptToUsableKey produces a real JWE ciphertext encrypted to pubKey
// with RSA-OAEP, for use in decryption tests.
func encryptToUsableKey(t *testing.T, payload []byte, pubKey any) []byte {
	t.Helper()
	ct, err := jwe.Encrypt(payload, jwe.WithKey(jwa.RSA_OAEP(), pubKey))
	require.NoError(t, err, "jwe.Encrypt should succeed")
	return ct
}

// TestDecryptWithKeySetSkipsUnsupportedKey covers the jwe.WithKeySet
// path, whose guard lives in keySetProvider.selectKey. A set holding both
// a usable decryption key and a placeholder decrypts via the usable key,
// never touching the placeholder. A set holding only the placeholder
// fails with no plaintext, and the retained parse reason surfaces.
func TestDecryptWithKeySetSkipsUnsupportedKey(t *testing.T) {
	rawKey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)

	payload := []byte("hello world")
	ct := encryptToUsableKey(t, payload, &rawKey.PublicKey)

	t.Run("usable key decrypts, placeholder skipped", func(t *testing.T) {
		usable, err := jwk.Import(rawKey)
		require.NoError(t, err)
		require.NoError(t, usable.Set(jwk.KeyIDKey, "rsa1"))
		require.NoError(t, usable.Set(jwk.AlgorithmKey, jwa.RSA_OAEP()))
		usableJSON, err := json.Marshal(usable)
		require.NoError(t, err)

		setJSON := []byte(`{"keys":[` + unknownEntryJSON + `,` + string(usableJSON) + `]}`)
		set, err := jwk.Parse(setJSON, jwk.WithStrictKeySetParsing(false))
		require.NoError(t, err)
		require.Equal(t, 2, set.Len())

		var used any
		got, err := jwe.Decrypt(ct, jwe.WithKeySet(set, jwe.WithRequireKid(false)), jwe.WithKeyUsed(&used))
		require.NoError(t, err)
		require.Equal(t, payload, got)

		usedKey, ok := used.(jwk.Key)
		require.True(t, ok, "used key should be a jwk.Key")
		require.False(t, jwk.IsUnsupportedKey(usedKey), "placeholder must never be the used key")
	})

	t.Run("placeholder-only set fails with no plaintext", func(t *testing.T) {
		set, err := jwk.Parse([]byte(`{"keys":[`+unknownEntryJSON+`]}`), jwk.WithStrictKeySetParsing(false))
		require.NoError(t, err)
		placeholder, ok := set.LookupKeyID("future1")
		require.True(t, ok)
		uk, ok := placeholder.(jwk.UnsupportedKey)
		require.True(t, ok)

		got, derr := jwe.Decrypt(ct, jwe.WithKeySet(set, jwe.WithRequireKid(false)))
		require.Error(t, derr)
		require.Nil(t, got, "no plaintext must be produced")
		require.Contains(t, derr.Error(), "future1", "error should name the kid")
		require.Contains(t, derr.Error(), "FUTURE", "error should name the unsupported kty")
		require.ErrorIs(t, derr, uk.Reason(), "retained parse reason should surface")
	})
}

// TestDecryptWithKeyRejectsPlaceholder covers the direct jwe.WithKey
// path. Decryption relies on jwe.Decrypt calling jwk.Export on the key
// before any crypto dispatch; Export rejects the placeholder, so
// decryption fails with no plaintext.
func TestDecryptWithKeyRejectsPlaceholder(t *testing.T) {
	placeholder := parseUnsupportedPlaceholder(t)

	rawKey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)
	ct := encryptToUsableKey(t, []byte("hello world"), &rawKey.PublicKey)

	got, derr := jwe.Decrypt(ct, jwe.WithKey(jwa.RSA_OAEP(), placeholder))
	require.Error(t, derr)
	require.Nil(t, got, "no plaintext must be produced")
	require.Contains(t, derr.Error(), "future1", "error should name the kid")
	require.Contains(t, derr.Error(), "FUTURE", "error should name the unsupported kty")
}

// TestEncryptWithKeyRejectsPlaceholder covers the direct jwe.WithKey
// encryption path. recipientBuilder.Build calls jwk.Export on the key
// before any crypto dispatch; Export rejects the placeholder, so
// encryption fails.
func TestEncryptWithKeyRejectsPlaceholder(t *testing.T) {
	placeholder := parseUnsupportedPlaceholder(t)

	ct, err := jwe.Encrypt([]byte("hello world"), jwe.WithKey(jwa.RSA_OAEP(), placeholder))
	require.Error(t, err)
	require.Nil(t, ct, "no ciphertext must be produced")
	require.Contains(t, err.Error(), "future1", "error should name the kid")
	require.Contains(t, err.Error(), "FUTURE", "error should name the unsupported kty")
}

// placeholderSinkProvider is a custom jwe.KeyProvider that sinks a fixed
// (alg, key) pair, bypassing the built-in key set provider and its
// selectKey guard entirely.
type placeholderSinkProvider struct {
	alg jwa.KeyEncryptionAlgorithm
	key jwk.Key
}

func (p placeholderSinkProvider) FetchKeys(_ context.Context, sink jwe.KeySink, _ jwe.Recipient, _ *jwe.Message) error {
	sink.Key(p.alg, p.key)
	return nil
}

// TestDecryptCustomKeyProviderRejectsPlaceholder covers a custom
// jwe.KeyProvider that sinks a placeholder directly, bypassing the
// built-in key set provider. The placeholder is still rejected by the
// jwk.Export call in the decrypt dispatch, so decryption fails with no
// plaintext.
func TestDecryptCustomKeyProviderRejectsPlaceholder(t *testing.T) {
	placeholder := parseUnsupportedPlaceholder(t)

	rawKey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)
	ct := encryptToUsableKey(t, []byte("hello world"), &rawKey.PublicKey)

	provider := placeholderSinkProvider{alg: jwa.RSA_OAEP(), key: placeholder}
	got, derr := jwe.Decrypt(ct, jwe.WithKeyProvider(provider))
	require.Error(t, derr)
	require.Nil(t, got, "no plaintext must be produced")
	require.Contains(t, derr.Error(), "future1", "error should name the kid")
	require.Contains(t, derr.Error(), "FUTURE", "error should name the unsupported kty")
}
