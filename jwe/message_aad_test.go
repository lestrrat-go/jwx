package jwe_test

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v3/internal/json"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/stretchr/testify/require"
)

func TestJWEJSONAADRoundTrip(t *testing.T) {
	t.Run("preserves external AAD", func(t *testing.T) {
		extAAD := []byte("external-aad")
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

		msg2, err := jwe.Parse(buf)
		require.NoError(t, err, `re-parse of the serialized message should succeed`)
		require.Equal(t, extAAD, msg2.AuthenticatedData(),
			`external AAD must be preserved across a serialization round trip`)
	})
}
