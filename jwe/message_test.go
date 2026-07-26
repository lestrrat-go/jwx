package jwe_test

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/stretchr/testify/require"

	"github.com/lestrrat-go/jwx/v4/jwe"
)

// TestJWEJSONAADRoundTrip pins RFC 7516 §7.2.1 — the "aad" member of the JWE
// JSON Serialization is BASE64URL(JWE AAD): the external Additional
// Authenticated Data alone, base64url-encoded with no padding. It must NOT
// carry the "protected header '.' aad" concatenation (that form is only the
// AEAD input, per §5.1/§5.2 step 14), and it must not be base64-encoded a
// second time. Before the fix, MarshalJSON emitted
// base64std(protectedB64 + "." + base64url(aad)), so a message carrying an
// external aad did not survive Parse -> json.Marshal -> Parse: the aad was
// silently corrupted (the lenient decoder accepts the mangled value without
// error).
func TestJWEJSONAADRoundTrip(t *testing.T) {
	extAAD := []byte("external-aad")
	// RFC 7516 §7.2.1: aad member == BASE64URL(JWE AAD).
	wantAADMember := base64.RawURLEncoding.EncodeToString(extAAD)
	protected := base64.RawURLEncoding.EncodeToString([]byte(`{"enc":"A128GCM"}`))
	src := fmt.Sprintf(
		`{"protected":%q,"encrypted_key":"","iv":"aXZpdml2aXZpdml2","ciphertext":"Y3Q","tag":"dGFn","aad":%q}`,
		protected, wantAADMember,
	)

	msg, err := jwe.Parse([]byte(src))
	require.NoError(t, err, `jwe.Parse should succeed`)
	require.Equal(t, extAAD, msg.AuthenticatedData(), `parsed aad should be the external AAD`)

	buf, err := json.Marshal(msg)
	require.NoError(t, err, `json.Marshal should succeed`)

	var got map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(buf, &got), `re-parse of serialized message should succeed`)
	var gotAAD string
	require.NoError(t, json.Unmarshal(got["aad"], &gotAAD), `aad member should be a JSON string`)
	require.Equal(t, wantAADMember, gotAAD,
		`serialized "aad" member must be BASE64URL(JWE AAD) per RFC 7516 §7.2.1`)

	// The message must survive a full Parse -> Marshal -> Parse cycle.
	msg2, err := jwe.Parse(buf)
	require.NoError(t, err, `re-parse of the serialized message should succeed`)
	require.Equal(t, extAAD, msg2.AuthenticatedData(),
		`external AAD must be preserved across a serialization round trip`)
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
