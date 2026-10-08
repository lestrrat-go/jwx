package jwe_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/require"
)

var headerUnionKey = bytes.Repeat([]byte{42}, 16)

// buildDirectJSONJWE seals "payload" with AES-128-GCM directly through the
// standard library, so that the header layout under test is not limited to
// what jwe.Encrypt can produce. A nil protected leaves the "protected" member
// out, which makes the AAD empty (RFC 7516 §5.1 step 14). Each element of
// recipients becomes one entry of "recipients"; a single element produces the
// flattened form instead when flattened is true.
func buildDirectJSONJWE(t *testing.T, protected *string, shared map[string]any, recipients []map[string]any, flattened bool) []byte {
	t.Helper()
	enc := base64.RawURLEncoding.EncodeToString

	obj := map[string]any{}
	var aad string
	if protected != nil {
		aad = enc([]byte(*protected))
		obj["protected"] = aad
	}

	block, err := aes.NewCipher(headerUnionKey)
	require.NoError(t, err, `aes.NewCipher should succeed`)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err, `cipher.NewGCM should succeed`)
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	require.NoError(t, err, `rand.Read should succeed`)
	sealed := gcm.Seal(nil, nonce, []byte("payload"), []byte(aad))
	split := len(sealed) - gcm.Overhead()
	obj["iv"] = enc(nonce)
	obj["ciphertext"] = enc(sealed[:split])
	obj["tag"] = enc(sealed[split:])

	if shared != nil {
		obj["unprotected"] = shared
	}

	if flattened {
		require.LessOrEqual(t, len(recipients), 1, `flattened form holds at most one recipient`)
		if len(recipients) == 1 && recipients[0] != nil {
			obj["header"] = recipients[0]
		}
	} else {
		list := make([]any, 0, len(recipients))
		for _, hdr := range recipients {
			entry := map[string]any{}
			if hdr != nil {
				entry["header"] = hdr
			}
			list = append(list, entry)
		}
		obj["recipients"] = list
	}

	wire, err := json.Marshal(obj)
	require.NoError(t, err, `json.Marshal should succeed`)
	return wire
}

// TestJSONHeaderUnion covers RFC 7516 §7.2.1: a recipient's JOSE header is
// the union of the protected header, the shared "unprotected" header, and
// the recipient's own "header", and a name may appear in only one of them.
func TestJSONHeaderUnion(t *testing.T) {
	t.Run("accepted placements", func(t *testing.T) {
		testcases := []struct {
			name      string
			protected *string
			shared    map[string]any
			recipient map[string]any
		}{
			{name: "alg and enc in protected header", protected: new(`{"alg":"dir","enc":"A128GCM"}`)},
			{name: "alg in shared header", protected: new(`{"enc":"A128GCM"}`), shared: map[string]any{jwe.AlgorithmKey: jwa.DIRECT().String()}},
			{name: "enc in shared header", protected: new(`{"alg":"dir"}`), shared: map[string]any{jwe.ContentEncryptionKey: jwa.A128GCM().String()}},
			{name: "enc in recipient header", protected: new(`{"alg":"dir"}`), recipient: map[string]any{jwe.ContentEncryptionKey: jwa.A128GCM().String()}},
			{name: "no protected member, shared header", shared: map[string]any{jwe.AlgorithmKey: jwa.DIRECT().String(), jwe.ContentEncryptionKey: jwa.A128GCM().String()}},
			{name: "no protected member, recipient header", recipient: map[string]any{jwe.AlgorithmKey: jwa.DIRECT().String(), jwe.ContentEncryptionKey: jwa.A128GCM().String()}},
			{name: "distinct private names", protected: new(`{"alg":"dir","enc":"A128GCM","p":1}`), shared: map[string]any{"s": 1}, recipient: map[string]any{"r": 1}},
		}
		for _, tc := range testcases {
			for _, flattened := range []bool{true, false} {
				name := tc.name + "/general"
				if flattened {
					name = tc.name + "/flattened"
				}
				t.Run(name, func(t *testing.T) {
					wire := buildDirectJSONJWE(t, tc.protected, tc.shared, []map[string]any{tc.recipient}, flattened)
					got, err := jwe.Decrypt(wire, jwe.WithKey(jwa.DIRECT(), headerUnionKey))
					require.NoError(t, err, `jwe.Decrypt should accept a valid header union`)
					require.Equal(t, []byte("payload"), got, `plaintext should match`)
				})
			}
		}
	})

	t.Run("rejected layouts", func(t *testing.T) {
		testcases := []struct {
			name       string
			protected  *string
			shared     map[string]any
			recipients []map[string]any
		}{
			{name: "kid in protected and recipient headers", protected: new(`{"alg":"dir","enc":"A128GCM","kid":"a"}`), recipients: []map[string]any{{jwe.KeyIDKey: "b"}}},
			{name: "same alg in protected and shared headers", protected: new(`{"alg":"dir","enc":"A128GCM"}`), shared: map[string]any{jwe.AlgorithmKey: jwa.DIRECT().String()}},
			{name: "private name in shared and recipient headers", protected: new(`{"alg":"dir","enc":"A128GCM"}`), shared: map[string]any{"x": true}, recipients: []map[string]any{{"x": true}}},
			{name: "private name in protected and shared headers", protected: new(`{"alg":"dir","enc":"A128GCM","x":true}`), shared: map[string]any{"x": true}},
			{name: "crit in shared header", protected: new(`{"alg":"dir","enc":"A128GCM"}`), shared: map[string]any{jwe.CriticalKey: []string{"x"}, "x": true}},
			{name: "crit in recipient header", protected: new(`{"alg":"dir","enc":"A128GCM"}`), recipients: []map[string]any{{jwe.CriticalKey: []string{"x"}, "x": true}}},
			{name: "zip in shared header", protected: new(`{"alg":"dir","enc":"A128GCM"}`), shared: map[string]any{jwe.CompressionKey: jwa.Deflate().String()}},
			{name: "zip in recipient header", protected: new(`{"alg":"dir","enc":"A128GCM"}`), recipients: []map[string]any{{jwe.CompressionKey: jwa.Deflate().String()}}},
			{name: "null crit in protected header", protected: new(`{"alg":"dir","enc":"A128GCM","crit":null}`)},
			{name: "null crit in shared header", protected: new(`{"alg":"dir","enc":"A128GCM"}`), shared: map[string]any{jwe.CriticalKey: nil}},
			{name: "empty protected member", protected: new(``), shared: map[string]any{jwe.AlgorithmKey: jwa.DIRECT().String(), jwe.ContentEncryptionKey: jwa.A128GCM().String()}},
		}
		for _, tc := range testcases {
			for _, flattened := range []bool{true, false} {
				name := tc.name + "/general"
				if flattened {
					name = tc.name + "/flattened"
				}
				t.Run(name, func(t *testing.T) {
					wire := buildDirectJSONJWE(t, tc.protected, tc.shared, tc.recipients, flattened)

					_, err := jwe.Parse(wire)
					require.Error(t, err, `jwe.Parse should reject the header layout`)
					require.ErrorIs(t, err, jwe.ParseError(), `error should be a jwe.ParseError`)

					_, err = jwe.Decrypt(wire, jwe.WithKey(jwa.DIRECT(), headerUnionKey))
					require.Error(t, err, `jwe.Decrypt should reject the header layout`)
					require.ErrorIs(t, err, jwe.DecryptError(), `error should be a jwe.DecryptError`)

					_, err = jwe.Decrypt(wire, jwe.WithKey(jwa.DIRECT(), headerUnionKey), jwe.WithCritValidation(false))
					require.Error(t, err, `jwe.Decrypt should reject the header layout even without crit validation`)
				})
			}
		}
	})

	t.Run("recipients disagree on enc", func(t *testing.T) {
		testcases := []struct {
			name       string
			recipients []map[string]any
		}{
			{name: "different values", recipients: []map[string]any{{jwe.ContentEncryptionKey: jwa.A128GCM().String()}, {jwe.ContentEncryptionKey: jwa.A256GCM().String()}}},
			{name: "one recipient without enc", recipients: []map[string]any{{jwe.ContentEncryptionKey: jwa.A128GCM().String()}, {}}},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				wire := buildDirectJSONJWE(t, new(`{"alg":"dir"}`), nil, tc.recipients, false)
				_, err := jwe.Parse(wire)
				require.Error(t, err, `jwe.Parse should reject recipients that disagree on enc`)
				require.ErrorIs(t, err, jwe.ParseError(), `error should be a jwe.ParseError`)
			})
		}
	})

	t.Run("message without protected member survives a round trip", func(t *testing.T) {
		wire := buildDirectJSONJWE(t, nil, map[string]any{jwe.AlgorithmKey: jwa.DIRECT().String(), jwe.ContentEncryptionKey: jwa.A128GCM().String()}, nil, true)
		msg, err := jwe.Parse(wire)
		require.NoError(t, err, `jwe.Parse should accept a message without "protected"`)

		serialized, err := json.Marshal(msg)
		require.NoError(t, err, `json.Marshal should succeed`)
		var members map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(serialized, &members), `serialized message should be a JSON object`)
		_, ok := members["protected"]
		require.False(t, ok, `serialized message should not gain a "protected" member`)

		got, err := jwe.Decrypt(serialized, jwe.WithKey(jwa.DIRECT(), headerUnionKey))
		require.NoError(t, err, `re-serialized message should decrypt`)
		require.Equal(t, []byte("payload"), got, `plaintext should match`)
	})
}

// TestJSONHeaderUnionKeySet checks that jwe.WithKeySet finds "kid" and "alg"
// wherever the JOSE header carries them, not only in the recipient header.
func TestJSONHeaderUnionKeySet(t *testing.T) {
	key, err := jwk.Import[jwk.Key](headerUnionKey)
	require.NoError(t, err, `jwk.Import should succeed`)
	require.NoError(t, key.Set(jwk.KeyIDKey, "k1"), `setting kid should succeed`)
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(key), `adding the key should succeed`)

	testcases := []struct {
		name      string
		protected *string
		shared    map[string]any
	}{
		{name: "kid and alg in protected header", protected: new(`{"alg":"dir","enc":"A128GCM","kid":"k1"}`)},
		{name: "kid and alg in shared header", protected: new(`{"enc":"A128GCM"}`), shared: map[string]any{jwe.AlgorithmKey: jwa.DIRECT().String(), jwe.KeyIDKey: "k1"}},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			wire := buildDirectJSONJWE(t, tc.protected, tc.shared, nil, true)
			got, err := jwe.Decrypt(wire, jwe.WithKeySet(set))
			require.NoError(t, err, `jwe.Decrypt should select the key by kid`)
			require.Equal(t, []byte("payload"), got, `plaintext should match`)
		})
	}

	t.Run("flattened output of jwe.Encrypt", func(t *testing.T) {
		encrypted, err := jwe.Encrypt([]byte("payload"),
			jwe.WithKey(jwa.A128KW(), key),
			jwe.WithContentEncryption(jwa.A128GCM()),
			jwe.WithJSON(),
		)
		require.NoError(t, err, `jwe.Encrypt should succeed`)

		got, err := jwe.Decrypt(encrypted, jwe.WithKeySet(set))
		require.NoError(t, err, `jwe.Decrypt should find the kid that jwe.Encrypt moved into the protected header`)
		require.Equal(t, []byte("payload"), got, `plaintext should match`)
	})
}

// TestEncryptRejectsInvalidHeaderPlacement checks that jwe.Encrypt does not
// write a general JSON message that jwe.Decrypt would reject.
func TestEncryptRejectsInvalidHeaderPlacement(t *testing.T) {
	k1 := bytes.Repeat([]byte{1}, 16)
	k2 := bytes.Repeat([]byte{2}, 16)

	headersWith := func(t *testing.T, kv map[string]any) jwe.Headers {
		t.Helper()
		h := jwe.NewHeaders()
		for k, v := range kv {
			require.NoError(t, h.Set(k, v), `setting %q should succeed`, k)
		}
		return h
	}

	testcases := []struct {
		name      string
		protected map[string]any
		recipient map[string]any
	}{
		{name: "kid in protected and recipient headers", protected: map[string]any{jwe.KeyIDKey: "p"}, recipient: map[string]any{jwe.KeyIDKey: "r"}},
		{name: "private name in protected and recipient headers", protected: map[string]any{"x": "p"}, recipient: map[string]any{"x": "r"}},
		{name: "alg in protected header", protected: map[string]any{jwe.AlgorithmKey: jwa.A128KW()}},
		{name: "enc in recipient header", recipient: map[string]any{jwe.ContentEncryptionKey: jwa.A128GCM()}},
		{name: "zip in recipient header", recipient: map[string]any{jwe.CompressionKey: jwa.Deflate()}},
		{name: "crit in recipient header", recipient: map[string]any{jwe.CriticalKey: []string{"x"}, "x": true}},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var options []jwe.EncryptOption
			if tc.protected != nil {
				options = append(options, jwe.WithProtectedHeaders(headersWith(t, tc.protected)))
			}
			var suboptions []jwe.WithKeySuboption
			if tc.recipient != nil {
				suboptions = append(suboptions, jwe.WithPerRecipientHeaders(headersWith(t, tc.recipient)))
			}

			general := append([]jwe.EncryptOption{
				jwe.WithJSON(),
				jwe.WithKey(jwa.A128KW(), k1, suboptions...),
				jwe.WithKey(jwa.A128KW(), k2),
			}, options...)
			_, err := jwe.Encrypt([]byte("payload"), general...)
			require.Error(t, err, `jwe.Encrypt should reject the header layout for general JSON`)
			require.ErrorIs(t, err, jwe.EncryptError(), `error should be a jwe.EncryptError`)

			// A single recipient is written in flattened form, where the
			// recipient header is merged into the protected header, so the
			// same options do not put a name in two places.
			flattened := append([]jwe.EncryptOption{
				jwe.WithJSON(),
				jwe.WithKey(jwa.A128KW(), k1, suboptions...),
			}, options...)
			_, err = jwe.Encrypt([]byte("payload"), flattened...)
			require.NoError(t, err, `jwe.Encrypt should accept the options for flattened JSON`)
		})
	}

	t.Run("disjoint headers are accepted", func(t *testing.T) {
		encrypted, err := jwe.Encrypt([]byte("payload"),
			jwe.WithJSON(),
			jwe.WithProtectedHeaders(headersWith(t, map[string]any{"p": 1})),
			jwe.WithKey(jwa.A128KW(), k1, jwe.WithPerRecipientHeaders(headersWith(t, map[string]any{"r": 1}))),
			jwe.WithKey(jwa.A128KW(), k2),
		)
		require.NoError(t, err, `jwe.Encrypt should accept disjoint headers`)
		for _, key := range [][]byte{k1, k2} {
			got, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.A128KW(), key))
			require.NoError(t, err, `jwe.Decrypt should succeed for each recipient`)
			require.Equal(t, []byte("payload"), got, `plaintext should match`)
		}
	})
}

// TestMarshalRecipientHeaderCopy checks how json.Marshal writes a recipient
// header that parsing copied from the protected header.
func TestMarshalRecipientHeaderCopy(t *testing.T) {
	compact, err := jwe.Encrypt([]byte("payload"),
		jwe.WithKey(jwa.A128KW(), headerUnionKey),
		jwe.WithContentEncryption(jwa.A128GCM()),
	)
	require.NoError(t, err, `jwe.Encrypt should succeed`)

	t.Run("copied names are left out", func(t *testing.T) {
		msg, err := jwe.Parse(compact)
		require.NoError(t, err, `jwe.Parse should succeed`)
		alg, ok := msg.Recipients()[0].Headers().Algorithm()
		require.True(t, ok, `recipient header should carry the copied alg`)
		require.Equal(t, jwa.A128KW(), alg, `copied alg should match`)

		serialized, err := json.Marshal(msg)
		require.NoError(t, err, `json.Marshal should succeed`)
		var members map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(serialized, &members), `serialized message should be a JSON object`)
		_, ok = members["header"]
		require.False(t, ok, `serialized message should not repeat the protected header in "header"`)

		got, err := jwe.Decrypt(serialized, jwe.WithKey(jwa.A128KW(), headerUnionKey))
		require.NoError(t, err, `serialized message should decrypt`)
		require.Equal(t, []byte("payload"), got, `plaintext should match`)
	})

	t.Run("names added after parsing are kept", func(t *testing.T) {
		msg, err := jwe.Parse(compact)
		require.NoError(t, err, `jwe.Parse should succeed`)
		require.NoError(t, msg.Recipients()[0].Headers().Set(jwe.KeyIDKey, "added"), `setting kid should succeed`)

		serialized, err := json.Marshal(msg)
		require.NoError(t, err, `json.Marshal should succeed`)
		var members map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(serialized, &members), `serialized message should be a JSON object`)
		require.JSONEq(t, `{"kid":"added"}`, string(members["header"]), `"header" should hold only the added name`)
	})

	t.Run("changed copied value is an error", func(t *testing.T) {
		msg, err := jwe.Parse(compact)
		require.NoError(t, err, `jwe.Parse should succeed`)
		require.NoError(t, msg.Recipients()[0].Headers().Set(jwe.AlgorithmKey, jwa.A256KW()), `setting alg should succeed`)

		_, err = json.Marshal(msg)
		require.Error(t, err, `json.Marshal should refuse to write "alg" with two values`)
	})
}
