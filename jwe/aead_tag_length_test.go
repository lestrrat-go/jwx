package jwe_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"
	"github.com/stretchr/testify/require"
)

// b64url decodes a base64url (no padding) string used by JWE wire fields.
func b64urlDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	require.NoError(t, err, "base64url decode should succeed")
	return b
}

func b64urlEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// encryptFlattened produces a flattened-JSON JWE and returns its parsed map.
func encryptFlattened(t *testing.T, payload, cek []byte, enc jwa.ContentEncryptionAlgorithm) map[string]any {
	t.Helper()
	encrypted, err := jwe.Encrypt(payload,
		jwe.WithKey(jwa.DIRECT(), cek),
		jwe.WithContentEncryption(enc),
		jwe.WithJSON(),
	)
	require.NoError(t, err, "jwe.Encrypt should succeed")

	var m map[string]any
	require.NoError(t, json.Unmarshal(encrypted, &m), "JWE should be valid JSON")
	return m
}

func marshalJSON(t *testing.T, m map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	require.NoError(t, err, "re-marshal should succeed")
	return b
}

func TestAEADWireLengthEnforcement(t *testing.T) {
	t.Parallel()

	const payload = "the quick brown fox jumps over the lazy dog"

	type tc struct {
		name string
		enc  jwa.ContentEncryptionAlgorithm
		cek  []byte
	}
	cases := []tc{
		{
			name: "A128GCM",
			enc:  jwa.A128GCM(),
			cek:  make([]byte, 16),
		},
		{
			name: "A128CBC-HS256",
			enc:  jwa.A128CBC_HS256(),
			cek:  make([]byte, 32),
		},
	}

	for i := range cases {
		c := cases[i]
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			// (a) Control: a normally-encrypted JWE round-trips. For CBC this
			// proves a valid message with len(tag)==16 is NOT rejected.
			t.Run("valid message decrypts", func(t *testing.T) {
				m := encryptFlattened(t, []byte(payload), c.cek, c.enc)
				got, err := jwe.Decrypt(marshalJSON(t, m), jwe.WithKey(jwa.DIRECT(), c.cek))
				require.NoError(t, err, "valid JWE should decrypt")
				require.Equal(t, payload, string(got))
			})

			// (b) Tag/ciphertext malleability: shift one byte from the tag
			// into the ciphertext. The concatenated AEAD input is unchanged,
			// so an unguarded GCM decrypt would still succeed.
			t.Run("tag/ciphertext byte shift rejected", func(t *testing.T) {
				m := encryptFlattened(t, []byte(payload), c.cek, c.enc)

				ct := b64urlDecode(t, m["ciphertext"].(string))
				tag := b64urlDecode(t, m["tag"].(string))
				require.NotEmpty(t, tag, "tag must be present")

				// Move the first tag byte to the end of the ciphertext.
				ct = append(ct, tag[0])
				tag = tag[1:]
				m["ciphertext"] = b64urlEncode(ct)
				m["tag"] = b64urlEncode(tag)

				_, err := jwe.Decrypt(marshalJSON(t, m), jwe.WithKey(jwa.DIRECT(), c.cek))
				require.Error(t, err, "shifted tag/ciphertext must be rejected")
			})

			// (c) Wrong-length IV is rejected.
			t.Run("wrong-length IV rejected", func(t *testing.T) {
				m := encryptFlattened(t, []byte(payload), c.cek, c.enc)

				iv := b64urlDecode(t, m["iv"].(string))
				iv = append(iv, 0x00) // one byte too long
				m["iv"] = b64urlEncode(iv)

				_, err := jwe.Decrypt(marshalJSON(t, m), jwe.WithKey(jwa.DIRECT(), c.cek))
				require.Error(t, err, "wrong-length IV must be rejected")
			})
		})
	}
}
