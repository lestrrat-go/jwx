package jws_test

import (
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/require"
)

// TestDetachedPayloadMemberPresence verifies that detached-payload
// verification treats a JSON JWS that explicitly carries a (possibly empty)
// "payload" member differently from one that omits it. RFC 7515 Appendix F
// detached form omits the member entirely; a present-but-empty "payload":""
// is an in-band JWS over an empty payload and must not silently accept a
// caller-supplied detached payload.
func TestDetachedPayloadMemberPresence(t *testing.T) {
	external := []byte("Lorem ipsum dolor sit amet")

	privkey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err, `jwxtest.GenerateRsaKey should succeed`)
	pubkey := &privkey.PublicKey

	// Build a true detached JWS (compact) over the external payload.
	compact, err := jws.Sign(nil, jws.WithKey(jwa.RS256(), privkey), jws.WithDetachedPayload(external))
	require.NoError(t, err, `jws.Sign (detached) should succeed`)

	t.Run("reject flattened JSON with present-but-empty payload", func(t *testing.T) {
		// Parse the detached compact form into a flattened JSON form,
		// then set "payload" to the empty string explicitly. This is the
		// ambiguous case: the member is present (even though empty), so it
		// must NOT be treated as a true detached JWS.
		msg, err := jws.Parse(compact)
		require.NoError(t, err, `jws.Parse should succeed`)

		jsonbuf, err := json.Marshal(msg)
		require.NoError(t, err, `json.Marshal should succeed`)

		var obj map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(jsonbuf, &obj), `json.Unmarshal should succeed`)
		obj["payload"] = json.RawMessage(`""`)
		tampered, err := json.Marshal(obj)
		require.NoError(t, err, `json.Marshal (tampered) should succeed`)

		_, err = jws.Verify(tampered, jws.WithKey(jwa.RS256(), pubkey), jws.WithDetachedPayload(external))
		require.Error(t, err, `jws.Verify must reject detached payload when "payload" member is present`)
	})

	t.Run("reject general JSON with present-but-empty payload", func(t *testing.T) {
		general := `{"payload":"","signatures":[` + extractSignatureEntry(t, compact) + `]}`
		_, err := jws.Verify([]byte(general), jws.WithKey(jwa.RS256(), pubkey), jws.WithDetachedPayload(external))
		require.Error(t, err, `jws.Verify must reject detached payload when "payload" member is present (general form)`)
	})

	t.Run("allow true detached JSON with omitted payload", func(t *testing.T) {
		// Same flattened JSON, but with the "payload" member omitted
		// entirely. This is a genuine detached JWS and must verify.
		msg, err := jws.Parse(compact)
		require.NoError(t, err, `jws.Parse should succeed`)
		jsonbuf, err := json.Marshal(msg)
		require.NoError(t, err, `json.Marshal should succeed`)

		var obj map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(jsonbuf, &obj), `json.Unmarshal should succeed`)
		delete(obj, "payload")
		detachedJSON, err := json.Marshal(obj)
		require.NoError(t, err, `json.Marshal (detached) should succeed`)

		_, err = jws.Verify(detachedJSON, jws.WithKey(jwa.RS256(), pubkey), jws.WithDetachedPayload(external))
		require.NoError(t, err, `jws.Verify must accept detached payload when "payload" member is omitted`)
	})

	t.Run("reject detached JSON with null payload", func(t *testing.T) {
		// A "payload":null member is present on the wire (so it is not a
		// true detached JWS), and null is not a valid base64url payload
		// string. It must be rejected, never treated as detached.
		msg, err := jws.Parse(compact)
		require.NoError(t, err, `jws.Parse should succeed`)
		jsonbuf, err := json.Marshal(msg)
		require.NoError(t, err, `json.Marshal should succeed`)

		var obj map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(jsonbuf, &obj), `json.Unmarshal should succeed`)
		obj["payload"] = json.RawMessage(`null`)
		tampered, err := json.Marshal(obj)
		require.NoError(t, err, `json.Marshal (tampered) should succeed`)

		_, err = jws.Verify(tampered, jws.WithKey(jwa.RS256(), pubkey), jws.WithDetachedPayload(external))
		require.Error(t, err, `jws.Verify must reject "payload":null and not treat it as detached`)
	})

	t.Run("reject normal JSON verification with null payload", func(t *testing.T) {
		// A null payload is invalid even for ordinary (non-detached)
		// verification: RFC 7515 payload is base64url text, not JSON null.
		// Assert it errors out cleanly (no panic).
		msg, err := jws.Parse(compact)
		require.NoError(t, err, `jws.Parse should succeed`)
		jsonbuf, err := json.Marshal(msg)
		require.NoError(t, err, `json.Marshal should succeed`)

		var obj map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(jsonbuf, &obj), `json.Unmarshal should succeed`)
		obj["payload"] = json.RawMessage(`null`)
		tampered, err := json.Marshal(obj)
		require.NoError(t, err, `json.Marshal (tampered) should succeed`)

		_, err = jws.Verify(tampered, jws.WithKey(jwa.RS256(), pubkey))
		require.Error(t, err, `jws.Verify must reject "payload":null in normal verification`)
	})

	t.Run("allow true detached compact (empty middle segment)", func(t *testing.T) {
		_, err := jws.Verify(compact, jws.WithKey(jwa.RS256(), pubkey), jws.WithDetachedPayload(external))
		require.NoError(t, err, `jws.Verify must accept detached compact JWS`)
	})

	t.Run("reject compact with non-empty payload and detached option", func(t *testing.T) {
		inband, err := jws.Sign(external, jws.WithKey(jwa.RS256(), privkey))
		require.NoError(t, err, `jws.Sign (in-band) should succeed`)
		_, err = jws.Verify(inband, jws.WithKey(jwa.RS256(), pubkey), jws.WithDetachedPayload(external))
		require.Error(t, err, `jws.Verify must reject detached option when compact JWS carries a payload`)
	})

	t.Run("normal in-band JSON verification still works", func(t *testing.T) {
		inband, err := jws.Sign(external, jws.WithKey(jwa.RS256(), privkey), jws.WithJSON())
		require.NoError(t, err, `jws.Sign (in-band JSON) should succeed`)
		payload, err := jws.Verify(inband, jws.WithKey(jwa.RS256(), pubkey))
		require.NoError(t, err, `jws.Verify (in-band JSON) should succeed`)
		require.Equal(t, external, payload, `payload should round-trip`)
	})
}

// extractSignatureEntry parses a detached compact JWS and returns a single
// general-form signature entry object (JSON) carrying its "protected" and
// "signature" members.
func extractSignatureEntry(t *testing.T, compact []byte) string {
	t.Helper()
	msg, err := jws.Parse(compact)
	require.NoError(t, err, `jws.Parse should succeed`)
	jsonbuf, err := json.Marshal(msg)
	require.NoError(t, err, `json.Marshal should succeed`)

	var obj map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(jsonbuf, &obj), `json.Unmarshal should succeed`)

	entry := map[string]json.RawMessage{
		"protected": obj["protected"],
		"signature": obj["signature"],
	}
	entrybuf, err := json.Marshal(entry)
	require.NoError(t, err, `json.Marshal (entry) should succeed`)
	return string(entrybuf)
}
