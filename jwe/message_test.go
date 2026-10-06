package jwe_test

import (
	"bytes"
	"testing"

	"github.com/lestrrat-go/jwx/v3/internal/json"
	"github.com/stretchr/testify/require"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
)

func TestJWESharedUnprotectedHeadersRoundTrip(t *testing.T) {
	t.Run("RFC7516AppendixA5", func(t *testing.T) {
		// https://www.rfc-editor.org/rfc/rfc7516#appendix-A.5
		const source = `{
			"protected":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
			"unprotected":{"jku":"https://server.example.com/keys.jwks"},
			"header":{"alg":"A128KW","kid":"7"},
			"encrypted_key":"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
			"iv":"AxY8DCtDaGlsbGljb3RoZQ",
			"ciphertext":"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
			"tag":"Mz-VPPyU4RlcuYv1IwIvzw"
		}`
		message, err := jwe.Parse([]byte(source))
		require.NoError(t, err)
		serialized, err := json.Marshal(message)
		require.NoError(t, err)
		require.JSONEq(t, source, string(serialized))
	})

	key := bytes.Repeat([]byte{1}, 32)
	payload := []byte("shared unprotected headers")
	encrypted, err := jwe.Encrypt(payload, jwe.WithKey(jwa.DIRECT(), key), jwe.WithContentEncryption(jwa.A256GCM()), jwe.WithJSON())
	require.NoError(t, err)
	var members map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(encrypted, &members))
	members["unprotected"] = json.RawMessage(`{"kid":"shared-key","custom":"quotes: \" and slash: \\"}`)
	source, err := json.Marshal(members)
	require.NoError(t, err)
	message, err := jwe.Parse(source)
	require.NoError(t, err)
	serialized, err := json.Marshal(message)
	require.NoError(t, err)
	var got map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(serialized, &got))
	require.JSONEq(t, string(members["unprotected"]), string(got["unprotected"]), "unprotected must remain a JSON object")
	for _, name := range []string{"protected", "ciphertext", "iv", "tag"} {
		require.Equal(t, members[name], got[name], "cryptographic member %s must be preserved", name)
	}
	reparsed, err := jwe.Parse(serialized)
	require.NoError(t, err)
	kid, ok := reparsed.UnprotectedHeaders().KeyID()
	require.True(t, ok)
	require.Equal(t, "shared-key", kid)
	decrypted, err := jwe.Decrypt(serialized, jwe.WithKey(jwa.DIRECT(), key))
	require.NoError(t, err)
	require.Equal(t, payload, decrypted)
}

func TestRecipient(t *testing.T) {
	t.Run("JSON Marshaling", func(t *testing.T) {
		const src = `{"header":{"foo":"bar"},"encrypted_key":"Zm9vYmFyYmF6"}`
		r1 := jwe.NewRecipient()

		require.NoError(t, json.Unmarshal([]byte(src), r1), `json.Unmarshal should succeed`)

		buf, err := json.Marshal(r1)
		require.NoError(t, err, `json.Marshal should succeed`)
		require.Equal(t, []byte(src), buf, `json representation should match`)
	})
}

// Ciphertext must be a string (possibly empty), while IV and tag must be
// present and non-empty. In particular, empty ciphertext must not allow an
// empty authentication tag to reach the AEAD verification code path.
func TestJWEJSONRejectsInvalidCryptoFields(t *testing.T) {
	// Minimal protected headers "{}" base64url-encoded = "e30".
	testcases := []struct {
		name string
		body string
	}{
		{"missing ciphertext", `{"protected":"e30","iv":"AAAA","tag":"AAAA","recipients":[{}]}`},
		{"null ciphertext", `{"protected":"e30","ciphertext":null,"iv":"AAAA","tag":"AAAA","recipients":[{}]}`},
		{"non-string ciphertext", `{"protected":"e30","ciphertext":42,"iv":"AAAA","tag":"AAAA","recipients":[{}]}`},
		{"empty ciphertext and tag", `{"protected":"e30","ciphertext":"","iv":"AAAA","tag":"","recipients":[{}]}`},
		{"missing iv", `{"protected":"e30","ciphertext":"AAAA","tag":"AAAA","recipients":[{}]}`},
		{"empty iv", `{"protected":"e30","ciphertext":"AAAA","iv":"","tag":"AAAA","recipients":[{}]}`},
		{"missing tag", `{"protected":"e30","ciphertext":"AAAA","iv":"AAAA","recipients":[{}]}`},
		{"empty tag", `{"protected":"e30","ciphertext":"AAAA","iv":"AAAA","tag":"","recipients":[{}]}`},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := jwe.Parse([]byte(tc.body))
			require.Error(t, err, `jwe.Parse should reject JWE JSON with invalid crypto fields`)
		})
	}
}
