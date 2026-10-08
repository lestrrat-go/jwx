package jwe_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"
	"github.com/stretchr/testify/require"
)

// useLenientHeaderRules turns off jwe.WithStrictHeaderRules for the rest of
// the test. Tests that call it must not call t.Parallel: the setting is
// process-wide. Go starts top-level parallel tests only after every
// sequential top-level test has finished, so the setting is restored before
// any of them runs.
func useLenientHeaderRules(t *testing.T) {
	t.Helper()
	require.NoError(t, jwe.Settings(jwe.WithStrictHeaderRules(false)), `jwe.Settings should succeed`)
	t.Cleanup(func() {
		require.NoError(t, jwe.Settings(jwe.WithStrictHeaderRules(true)), `restoring jwe.Settings should succeed`)
	})
}

// TestStrictHeaderRulesDisabled checks that jwe.WithStrictHeaderRules(false)
// restores the header handling from before the RFC 7516 §7.2.1 rules were
// enforced: header layouts that strict mode rejects are accepted again, and
// the shared "unprotected" header does not supply "alg" or "enc".
func TestStrictHeaderRulesDisabled(t *testing.T) {
	useLenientHeaderRules(t)

	t.Run("layouts rejected in strict mode decrypt", func(t *testing.T) {
		testcases := []struct {
			name       string
			protected  *string
			shared     map[string]any
			recipients []map[string]any
		}{
			{name: "kid in protected and per-recipient headers", protected: new(`{"alg":"dir","enc":"A128GCM","kid":"a"}`), recipients: []map[string]any{{jwe.KeyIDKey: "b"}}},
			{name: "same alg in protected and shared headers", protected: new(`{"alg":"dir","enc":"A128GCM"}`), shared: map[string]any{jwe.AlgorithmKey: jwa.DIRECT().String()}},
			{name: "private name in shared and recipient headers", protected: new(`{"alg":"dir","enc":"A128GCM"}`), shared: map[string]any{"x": true}, recipients: []map[string]any{{"x": true}}},
			{name: "crit in shared header", protected: new(`{"alg":"dir","enc":"A128GCM"}`), shared: map[string]any{jwe.CriticalKey: []string{"x"}, "x": true}},
			{name: "crit in per-recipient header", protected: new(`{"alg":"dir","enc":"A128GCM"}`), recipients: []map[string]any{{jwe.CriticalKey: []string{"x"}, "x": true}}},
			{name: "zip in shared header", protected: new(`{"alg":"dir","enc":"A128GCM"}`), shared: map[string]any{jwe.CompressionKey: jwa.Deflate().String()}},
			{name: "zip in per-recipient header", protected: new(`{"alg":"dir","enc":"A128GCM"}`), recipients: []map[string]any{{jwe.CompressionKey: jwa.Deflate().String()}}},
		}
		for _, tc := range testcases {
			for _, flattened := range []bool{true, false} {
				name := tc.name + "/general"
				if flattened {
					name = tc.name + "/flattened"
				}
				t.Run(name, func(t *testing.T) {
					wire := buildDirectJSONJWE(t, tc.protected, tc.shared, tc.recipients, flattened)
					got, err := jwe.Decrypt(wire, jwe.WithKey(jwa.DIRECT(), headerUnionKey))
					require.NoError(t, err, `jwe.Decrypt should accept the layout when strict header rules are off`)
					require.Equal(t, []byte("payload"), got, `plaintext should match`)
				})
			}
		}
	})

	t.Run("null crit is still rejected", func(t *testing.T) {
		testcases := []struct {
			name      string
			protected *string
			shared    map[string]any
		}{
			{name: "protected header", protected: new(`{"alg":"dir","enc":"A128GCM","crit":null}`)},
			{name: "shared header", protected: new(`{"alg":"dir","enc":"A128GCM"}`), shared: map[string]any{jwe.CriticalKey: nil}},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				wire := buildDirectJSONJWE(t, tc.protected, tc.shared, nil, true)
				_, err := jwe.Parse(wire)
				require.Error(t, err, `jwe.Parse should reject a null crit even when strict header rules are off`)
			})
		}

		t.Run("compact", func(t *testing.T) {
			protected := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"dir","enc":"A128GCM","crit":null}`))
			_, err := jwe.Parse([]byte(protected + "..aXZpdml2aXZpdml2.Y3Q.dGFn"))
			require.Error(t, err, `jwe.Parse should reject a null crit in a compact message`)
		})
	})

	t.Run("recipients that disagree on enc parse", func(t *testing.T) {
		wire := buildDirectJSONJWE(t, new(`{"alg":"dir"}`), nil, []map[string]any{
			{jwe.ContentEncryptionKey: jwa.A128GCM().String()},
			{jwe.ContentEncryptionKey: jwa.A256GCM().String()},
		}, false)
		_, err := jwe.Parse(wire)
		require.NoError(t, err, `jwe.Parse should accept the message when strict header rules are off`)
	})

	t.Run("alg and enc outside the protected header are ignored", func(t *testing.T) {
		testcases := []struct {
			name      string
			protected *string
			shared    map[string]any
			recipient map[string]any
		}{
			{name: "alg in shared header", protected: new(`{"enc":"A128GCM"}`), shared: map[string]any{jwe.AlgorithmKey: jwa.DIRECT().String()}},
			{name: "enc in shared header", protected: new(`{"alg":"dir"}`), shared: map[string]any{jwe.ContentEncryptionKey: jwa.A128GCM().String()}},
			{name: "enc in per-recipient header", protected: new(`{"alg":"dir"}`), recipient: map[string]any{jwe.ContentEncryptionKey: jwa.A128GCM().String()}},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				wire := buildDirectJSONJWE(t, tc.protected, tc.shared, []map[string]any{tc.recipient}, true)
				_, err := jwe.Decrypt(wire, jwe.WithKey(jwa.DIRECT(), headerUnionKey))
				require.Error(t, err, `jwe.Decrypt should not read alg or enc outside the protected header when strict header rules are off`)
			})
		}
	})

	t.Run("shared alg does not override the protected alg", func(t *testing.T) {
		wire := buildDirectJSONJWE(t, new(`{"alg":"dir","enc":"A128GCM"}`), map[string]any{jwe.AlgorithmKey: jwa.A128KW().String()}, nil, true)
		got, err := jwe.Decrypt(wire, jwe.WithKey(jwa.DIRECT(), headerUnionKey))
		require.NoError(t, err, `jwe.Decrypt should ignore the shared alg when strict header rules are off`)
		require.Equal(t, []byte("payload"), got, `plaintext should match`)
	})

	t.Run("encrypt writes overlapping recipient headers", func(t *testing.T) {
		protected := jwe.NewHeaders()
		require.NoError(t, protected.Set(jwe.KeyIDKey, "p"), `setting kid should succeed`)
		recipient := jwe.NewHeaders()
		require.NoError(t, recipient.Set(jwe.KeyIDKey, "r"), `setting kid should succeed`)

		k1 := bytes.Repeat([]byte{1}, 16)
		k2 := bytes.Repeat([]byte{2}, 16)
		encrypted, err := jwe.Encrypt([]byte("payload"),
			jwe.WithJSON(),
			jwe.WithProtectedHeaders(protected),
			jwe.WithKey(jwa.A128KW(), k1, jwe.WithPerRecipientHeaders(recipient)),
			jwe.WithKey(jwa.A128KW(), k2),
		)
		require.NoError(t, err, `jwe.Encrypt should accept overlapping headers when strict header rules are off`)

		got, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.A128KW(), k1))
		require.NoError(t, err, `jwe.Decrypt should accept the output when strict header rules are off`)
		require.Equal(t, []byte("payload"), got, `plaintext should match`)
	})

	t.Run("marshal writes a changed copied value", func(t *testing.T) {
		compact, err := jwe.Encrypt([]byte("payload"),
			jwe.WithKey(jwa.A128KW(), headerUnionKey),
			jwe.WithContentEncryption(jwa.A128GCM()),
		)
		require.NoError(t, err, `jwe.Encrypt should succeed`)
		msg, err := jwe.Parse(compact)
		require.NoError(t, err, `jwe.Parse should succeed`)
		require.NoError(t, msg.Recipients()[0].Headers().Set(jwe.AlgorithmKey, jwa.A256KW()), `setting alg should succeed`)

		serialized, err := json.Marshal(msg)
		require.NoError(t, err, `json.Marshal should write the header when strict header rules are off`)
		var members map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(serialized, &members), `serialized message should be a JSON object`)
		require.Contains(t, string(members["header"]), `"A256KW"`, `"header" should keep the changed alg`)
	})
}

// TestStrictHeaderRulesRestored checks that turning the setting back on
// brings back the strict checks.
func TestStrictHeaderRulesRestored(t *testing.T) {
	require.NoError(t, jwe.Settings(jwe.WithStrictHeaderRules(false)), `jwe.Settings should succeed`)
	require.NoError(t, jwe.Settings(jwe.WithStrictHeaderRules(true)), `jwe.Settings should succeed`)

	wire := buildDirectJSONJWE(t, new(`{"alg":"dir","enc":"A128GCM"}`), map[string]any{jwe.CompressionKey: jwa.Deflate().String()}, nil, true)
	_, err := jwe.Parse(wire)
	require.Error(t, err, `jwe.Parse should reject an unprotected zip once strict header rules are back on`)
}

// TestStrictHeaderRulesReadOncePerCall checks that jwe.Decrypt and
// jwe.Encrypt use the WithStrictHeaderRules value they read when they
// started, even when jwe.Settings changes it while they run. The change is
// made from inside a key provider or key encrypter, which runs in the middle
// of the call.
func TestStrictHeaderRulesReadOncePerCall(t *testing.T) {
	restore := func(t *testing.T) {
		t.Helper()
		t.Cleanup(func() {
			require.NoError(t, jwe.Settings(jwe.WithStrictHeaderRules(true)), `restoring jwe.Settings should succeed`)
		})
	}
	switchTo := func(strict bool) {
		// Errors cannot be returned from here; the restore cleanup and the
		// assertions below catch a failed switch.
		_ = jwe.Settings(jwe.WithStrictHeaderRules(strict))
	}

	t.Run("decrypt started strict", func(t *testing.T) {
		restore(t)
		// "enc" is only in the shared header, so only a strict call can
		// decrypt this message.
		wire := buildDirectJSONJWE(t, new(`{"alg":"dir"}`), map[string]any{jwe.ContentEncryptionKey: jwa.A128GCM().String()}, nil, true)
		kp := jwe.KeyProviderFunc(func(_ context.Context, sink jwe.KeySink, _ jwe.Recipient, _ *jwe.Message) error {
			switchTo(false)
			sink.Key(jwa.DIRECT(), headerUnionKey)
			return nil
		})
		got, err := jwe.Decrypt(wire, jwe.WithKeyProvider(kp))
		require.NoError(t, err, `jwe.Decrypt should keep the strict setting it started with`)
		require.Equal(t, []byte("payload"), got, `plaintext should match`)
	})

	t.Run("decrypt started lenient", func(t *testing.T) {
		restore(t)
		switchTo(false)
		// The shared header repeats "alg" with a different value. A lenient
		// parse accepts it; the decrypt step must then keep ignoring the
		// shared header instead of letting it replace the protected "alg".
		wire := buildDirectJSONJWE(t, new(`{"alg":"dir","enc":"A128GCM"}`), map[string]any{jwe.AlgorithmKey: jwa.A128KW().String()}, nil, true)
		kp := jwe.KeyProviderFunc(func(_ context.Context, sink jwe.KeySink, _ jwe.Recipient, _ *jwe.Message) error {
			switchTo(true)
			sink.Key(jwa.DIRECT(), headerUnionKey)
			return nil
		})
		got, err := jwe.Decrypt(wire, jwe.WithKeyProvider(kp))
		require.NoError(t, err, `jwe.Decrypt should keep the lenient setting it started with`)
		require.Equal(t, []byte("payload"), got, `plaintext should match`)
	})

	t.Run("encrypt started strict", func(t *testing.T) {
		restore(t)
		protected := jwe.NewHeaders()
		require.NoError(t, protected.Set(jwe.KeyIDKey, "p"), `setting kid should succeed`)
		recipient := jwe.NewHeaders()
		require.NoError(t, recipient.Set(jwe.KeyIDKey, "r"), `setting kid should succeed`)

		switching := jwe.KeyEncryptFunc{
			Alg: jwa.A128KW(),
			Encrypt: func(cek []byte) ([]byte, error) {
				switchTo(false)
				return bytes.Clone(cek), nil
			},
		}
		_, err := jwe.Encrypt([]byte("payload"),
			jwe.WithJSON(),
			jwe.WithProtectedHeaders(protected),
			jwe.WithKey(jwa.A128KW(), switching, jwe.WithPerRecipientHeaders(recipient)),
			jwe.WithKey(jwa.A128KW(), bytes.Repeat([]byte{2}, 16)),
		)
		require.Error(t, err, `jwe.Encrypt should keep the strict setting it started with`)
	})
}
