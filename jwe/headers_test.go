package jwe_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"reflect"
	"testing"

	"github.com/lestrrat-go/jwx/v4/cert"
	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/lestrrat-go/jwx/v4/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/require"
)

var zeroval reflect.Value

func TestHeaders(t *testing.T) {
	certSrc := []string{
		"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",
	}
	var certs cert.Chain
	for _, src := range certSrc {
		_ = certs.AddString(src)
	}

	rawKey, err := jwxtest.GenerateEcdsaKey(jwa.P521())
	require.NoError(t, err, `jwxtest.GenerateEcdsaKey should succeed`)
	privKey, err := jwk.Import[jwk.Key](rawKey)
	require.NoError(t, err, `jwk.Import should succeed`)

	pubKey, err := jwk.Import[jwk.Key](rawKey.PublicKey)
	require.NoError(t, err, `jwk.Import should succeed`)

	data := []struct {
		Key      string
		Value    any
		Expected any
		Method   string
	}{
		{
			Key:    jwe.AgreementPartyUInfoKey,
			Value:  []byte("apu foobarbaz"),
			Method: "AgreementPartyUInfo",
		},
		{Key: jwe.AgreementPartyVInfoKey, Value: []byte("apv foobarbaz")},
		{Key: jwe.CompressionKey, Value: jwa.Deflate()},
		{Key: jwe.ContentEncryptionKey, Value: jwa.A128GCM()},
		{
			Key:    jwe.ContentTypeKey,
			Value:  "application/json",
			Method: "ContentType",
		},
		{
			Key:    jwe.CriticalKey,
			Value:  []string{"crit blah"},
			Method: "Critical",
		},
		{
			Key:    jwe.EphemeralPublicKeyKey,
			Value:  pubKey,
			Method: "EphemeralPublicKey",
		},
		{
			Key:    jwe.JWKKey,
			Value:  privKey,
			Method: "JWK",
		},
		{
			Key:    jwe.JWKSetURLKey,
			Value:  "http://github.com/lestrrat-go/jwx/v4",
			Method: "JWKSetURL",
		},
		{
			Key:    jwe.KeyIDKey,
			Value:  "kid blah",
			Method: "KeyID",
		},
		{
			Key:    jwe.TypeKey,
			Value:  "typ blah",
			Method: "Type",
		},
		{
			Key:    jwe.X509CertChainKey,
			Value:  &certs,
			Method: "X509CertChain",
		},
		{
			Key:    jwe.X509CertThumbprintKey,
			Value:  "x5t blah",
			Method: "X509CertThumbprint",
		},
		{
			Key:    jwe.X509CertThumbprintS256Key,
			Value:  "x5t#256 blah",
			Method: "X509CertThumbprintS256",
		},
		{
			Key:    jwe.X509URLKey,
			Value:  "http://github.com/lestrrat-go/jwx/v4",
			Method: "X509URL",
		},
		{Key: "private", Value: "boofoo"},
	}

	base := jwe.NewHeaders()

	t.Run("Set values", func(t *testing.T) {
		// DO NOT RUN THIS IN PARALLEL. THIS IS AN INITIALIZER
		for _, tc := range data {
			require.NoError(t, base.Set(tc.Key, tc.Value), "Headers.Set should succeed")
		}
	})

	t.Run("Set/Field", func(t *testing.T) {
		h := jwe.NewHeaders()
		for _, k := range base.Keys() {
			v, ok := base.Field(k)
			require.True(t, ok, `base.Field should succeed for key %#v`, k)
			require.NoError(t, h.Set(k, v), `h.Set should succeed for key %#v`, k)
		}
		for _, tc := range data {
			var values []any
			viaGet, ok := h.Field(tc.Key)
			require.True(t, ok, `h.Field should succeed`)
			values = append(values, viaGet)

			if method := tc.Method; method != "" {
				m := reflect.ValueOf(h).MethodByName(method)
				require.NotEqual(t, m, zeroval, "method %s should be available", method)

				ret := m.Call(nil)
				require.Len(t, ret, 2, `should get exactly 1 value as return value`)
				values = append(values, ret[0].Interface())
			}

			expected := tc.Expected
			if expected == nil {
				expected = tc.Value
			}
			for i, got := range values {
				require.Equal(t, expected, got, "value %d should match", i)
			}
		}
	})
	t.Run("PrivateParams", func(t *testing.T) {
		h := base

		v, ok := h.Field(`private`)
		require.True(t, ok, `h.Field should succeed`)
		require.Equal(t, v, "boofoo", `value for 'private' should match`)
	})
	t.Run("Encode", func(t *testing.T) {
		h1 := jwe.NewHeaders()
		h1.Set(jwe.AlgorithmKey, jwa.A128GCMKW)
		h1.Set("foo", "bar")

		buf, err := h1.Encode()
		require.NoError(t, err, `h1.Encode should succeed`)

		h2 := jwe.NewHeaders()
		require.NoError(t, h2.Decode(buf), `h2.Decode should succeed`)

		require.Equal(t, h1, h2, `objects should match`)
	})

	t.Run("RejectInvalidX509CertChain", func(t *testing.T) {
		h := jwe.NewHeaders()
		err := json.Unmarshal([]byte(`{"x5c":["bm90IGEgY2VydGlmaWNhdGU="]}`), h)
		require.Error(t, err, `json.Unmarshal should reject invalid x5c entries`)
		require.False(t, h.Has(jwe.X509CertChainKey), `failed decode must not populate x5c`)
	})

	t.Run("Range", func(t *testing.T) {
		expected := map[string]any{}
		for _, tc := range data {
			v := tc.Value
			if expected := tc.Expected; expected != nil {
				v = expected
			}
			expected[tc.Key] = v
		}

		t.Run("Remove", func(t *testing.T) {
			h := base

			for _, k := range h.Keys() {
				require.NoError(t, h.Remove(k), `h.Remove should succeed`)
			}

			require.Len(t, h.Keys(), 0, `len should be zero`)
		})
	})
}

// A custom header name must never be able to introduce members of its own.
// See GHSA-4cf7-xm37-g63h.
func TestHeaderNameCannotInjectMembers(t *testing.T) {
	t.Parallel()

	const name = `x":0,"kid`

	hdrs := jwe.NewHeaders()
	require.NoError(t, hdrs.Set(name, "injected"), `Set should succeed`)

	buf, err := json.Marshal(hdrs)
	require.NoError(t, err, `json.Marshal should succeed`)

	var got map[string]any
	require.NoError(t, json.Unmarshal(buf, &got), `serialized headers should be valid JSON`)
	require.Len(t, got, 1, `exactly one header should be serialized: %s`, buf)
	require.Contains(t, got, name, `header name should round-trip unchanged: %s`, buf)

	roundtrip := jwe.NewHeaders()
	require.NoError(t, json.Unmarshal(buf, roundtrip), `headers should unmarshal`)
	kid, ok := roundtrip.KeyID()
	require.False(t, ok, `no "kid" header should have been injected, got %q`, kid)
}

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

// TestUnprotectedZipRejected verifies that a "zip" (compression) header
// injected into the per-recipient/unprotected header — which the AEAD does
// not authenticate — is rejected. RFC 7516 §4.1.3 only allows "zip" in the
// protected header, so only the protected header may control
// post-decryption decompression.
func TestUnprotectedZipRejected(t *testing.T) {
	const plaintext = `the quick brown fox jumps over the lazy dog`

	key, err := jwk.Import[jwk.SymmetricKey]([]byte(`0123456789abcdef`))
	require.NoError(t, err, `jwk.Import should succeed`)

	// Encrypt WITHOUT compression, in flattened JSON form. The protected
	// header therefore carries no "zip".
	encrypted, err := jwe.Encrypt([]byte(plaintext),
		jwe.WithKey(jwa.A128KW(), key),
		jwe.WithContentEncryption(jwa.A128CBC_HS256()),
		jwe.WithJSON(),
	)
	require.NoError(t, err, `jwe.Encrypt should succeed`)

	// Inject a malicious "zip":"DEF" into the unprotected per-recipient
	// "header" object. This is outside the AEAD-authenticated protected
	// header, so an attacker can add it without invalidating the tag.
	var obj map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(encrypted, &obj), `unmarshal serialized JWE`)
	_, hasZipInProtected := obj["zip"]
	require.False(t, hasZipInProtected, `top-level should not have zip`)
	obj["header"] = json.RawMessage(`{"zip":"DEF"}`)
	tampered, err := json.Marshal(obj)
	require.NoError(t, err, `re-marshal tampered JWE`)

	_, err = jwe.Decrypt(tampered, jwe.WithKey(jwa.A128KW(), key))
	require.Error(t, err, `jwe.Decrypt should reject an unprotected zip`)
	require.ErrorIs(t, err, jwe.ParseError(), `the message should be rejected while parsing`)
}

// TestProtectedZipRoundTrips is the control: compression requested through
// the protected header (via jwe.WithCompress) still round-trips correctly.
func TestProtectedZipRoundTrips(t *testing.T) {
	const plaintext = `the quick brown fox jumps over the lazy dog`

	key, err := jwk.Import[jwk.SymmetricKey]([]byte(`0123456789abcdef`))
	require.NoError(t, err, `jwk.Import should succeed`)

	encrypted, err := jwe.Encrypt([]byte(plaintext),
		jwe.WithKey(jwa.A128KW(), key),
		jwe.WithContentEncryption(jwa.A128CBC_HS256()),
		jwe.WithCompress(jwa.Deflate()),
	)
	require.NoError(t, err, `jwe.Encrypt should succeed`)

	decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.A128KW(), key))
	require.NoError(t, err, `jwe.Decrypt should succeed`)
	require.Equal(t, plaintext, string(decrypted), `compressed payload must round-trip`)
}
