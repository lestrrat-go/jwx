package jwe_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v3/internal/json"
	"github.com/stretchr/testify/require"

	"github.com/lestrrat-go/jwx/v3/jwe"
)

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

// TestJWEJSONRejectsEmptyCryptoFields pins RFC 7516 §7.2 — "ciphertext", "iv",
// and "tag" MUST be present and non-empty. Without this check, a zero-length
// authentication tag would reach the AEAD verification code path.
func TestJWEJSONRejectsEmptyCryptoFields(t *testing.T) {
	// Minimal protected headers "{}" base64url-encoded = "e30".
	testcases := []struct {
		name string
		body string
	}{
		{"missing ciphertext", `{"protected":"e30","iv":"AAAA","tag":"AAAA","recipients":[{}]}`},
		{"empty ciphertext", `{"protected":"e30","ciphertext":"","iv":"AAAA","tag":"AAAA","recipients":[{}]}`},
		{"missing iv", `{"protected":"e30","ciphertext":"AAAA","tag":"AAAA","recipients":[{}]}`},
		{"empty iv", `{"protected":"e30","ciphertext":"AAAA","iv":"","tag":"AAAA","recipients":[{}]}`},
		{"missing tag", `{"protected":"e30","ciphertext":"AAAA","iv":"AAAA","recipients":[{}]}`},
		{"empty tag", `{"protected":"e30","ciphertext":"AAAA","iv":"AAAA","tag":"","recipients":[{}]}`},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := jwe.Parse([]byte(tc.body))
			require.Error(t, err, `jwe.Parse should reject JWE JSON with missing/empty crypto fields`)
		})
	}
}
