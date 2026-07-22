package jwe

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/require"
)

// recordingKeySink implements jwe.KeySink and remembers every key handed to
// it, so a test can assert exactly which keys reached the sink. Unlike
// algKeySink it does nothing with the keys other than record them.
type recordingKeySink struct {
	keys []any
}

func (s *recordingKeySink) Key(_ jwa.KeyEncryptionAlgorithm, key any) {
	s.keys = append(s.keys, key)
}

// parsePlaceholderKey parses a single unknown-kty entry in retain mode and
// returns the resulting jwk.UnsupportedKey placeholder.
func parsePlaceholderKey(t *testing.T) jwk.UnsupportedKey {
	t.Helper()

	set, err := jwk.Parse([]byte(`{"keys":[{"kty":"FUTURE","kid":"future-1"}]}`), jwk.WithStrictKeySetParsing(false))
	require.NoError(t, err, `jwk.Parse in retain mode should succeed`)
	key, ok := set.Key(0)
	require.True(t, ok, `set should have one entry`)
	placeholder, ok := key.(jwk.UnsupportedKey)
	require.True(t, ok, `the only entry should be an UnsupportedKey placeholder`)
	require.True(t, jwk.IsUnsupportedKey(placeholder), `placeholder should report IsUnsupportedKey`)
	require.Error(t, placeholder.Reason(), `placeholder should retain its parse error`)
	return placeholder
}

// TestKeySetProviderSkipsUnsupportedKey is a white-box test that drives
// keySetProvider.FetchKeys directly with a recording KeySink to pin the
// UnsupportedKey guard in selectKey (jwe/key_provider.go). It deliberately
// gives the recipient an "alg" header so that, were the guard removed, the
// placeholder would fall through to the header-alg branch and be sunk — that
// is exactly the leak this test catches. The existing end-to-end WithKeySet
// test does not fail if the guard is deleted, because a usable key decrypts
// first and a downstream jwk.Export guard catches the placeholder-only case.
func TestKeySetProviderSkipsUnsupportedKey(t *testing.T) {
	t.Parallel()

	rawPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, `generating RSA key should succeed`)

	// A recipient that declares "alg" — this is what would let an
	// unguarded selectKey sink a placeholder via the header-alg fallback.
	recipientWithAlg := func(t *testing.T) Recipient {
		t.Helper()
		rec := NewRecipient()
		require.NoError(t, rec.Headers().Set(AlgorithmKey, jwa.RSA_OAEP()), `setting recipient alg should succeed`)
		return rec
	}

	t.Run("mixed set sinks only the usable key, never the placeholder", func(t *testing.T) {
		t.Parallel()

		usable, err := jwk.Import[jwk.Key](rawPriv)
		require.NoError(t, err, `importing RSA private key should succeed`)
		require.NoError(t, usable.Set(jwk.AlgorithmKey, jwa.RSA_OAEP()))
		require.NoError(t, usable.Set(jwk.KeyIDKey, "usable"))

		placeholder := parsePlaceholderKey(t)

		set := jwk.NewSet()
		require.NoError(t, set.AddKey(usable), `adding usable key should succeed`)
		require.NoError(t, set.AddKey(placeholder), `adding placeholder should succeed`)

		kp := &keySetProvider{set: set, requireKid: false}
		sink := &recordingKeySink{}
		err = kp.FetchKeys(t.Context(), sink, recipientWithAlg(t), NewMessage())
		require.NoError(t, err, `FetchKeys should succeed when a usable key is present`)

		// The usable key — and only the usable key — must reach the sink.
		require.Len(t, sink.keys, 1, `exactly one key should reach the sink`)
		sunk, ok := sink.keys[0].(jwk.Key)
		require.True(t, ok, `the sunk key should be a jwk.Key`)
		require.False(t, jwk.IsUnsupportedKey(sunk), `the placeholder must never reach the sink`)
		for _, k := range sink.keys {
			if key, ok := k.(jwk.Key); ok {
				require.False(t, jwk.IsUnsupportedKey(key), `no sunk key may be an UnsupportedKey placeholder`)
			}
		}
	})

	t.Run("placeholder-only set sinks nothing and returns the unsupported reason", func(t *testing.T) {
		t.Parallel()

		placeholder := parsePlaceholderKey(t)

		set := jwk.NewSet()
		require.NoError(t, set.AddKey(placeholder), `adding placeholder should succeed`)

		kp := &keySetProvider{set: set, requireKid: false}
		sink := &recordingKeySink{}
		err := kp.FetchKeys(t.Context(), sink, recipientWithAlg(t), NewMessage())
		require.Error(t, err, `FetchKeys must fail when the only key is a placeholder`)
		require.ErrorIs(t, err, placeholder.Reason(), `error should wrap the placeholder's unsupported reason`)
		require.Empty(t, sink.keys, `no key may reach the sink`)
	})
}
