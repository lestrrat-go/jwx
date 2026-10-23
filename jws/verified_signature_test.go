package jws_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/stretchr/testify/require"
)

const verifiedSignatureExt = "x-tenant-binding"

type signatureEntry struct {
	Protected string `json:"protected"`
	Signature string `json:"signature"`
}

type generalJSONJWS struct {
	Payload    string           `json:"payload"`
	Signatures []signatureEntry `json:"signatures"`
}

type flattenedJSONJWS struct {
	signatureEntry

	Payload string `json:"payload"`
}

// hmacSignatureEntry builds one signature entry of a JSON JWS by hand, so the
// tests control the order of entries and the key each one is signed with.
func hmacSignatureEntry(t *testing.T, payload, protected string, key []byte) signatureEntry {
	t.Helper()

	encoded := base64.RawURLEncoding.EncodeToString([]byte(protected))
	mac := hmac.New(sha256.New, key)
	_, err := mac.Write([]byte(encoded + "." + payload))
	require.NoError(t, err, `mac.Write should succeed`)
	return signatureEntry{
		Protected: encoded,
		Signature: base64.RawURLEncoding.EncodeToString(mac.Sum(nil)),
	}
}

func tenantProtectedHeader(tenant string) string {
	return `{"alg":"HS256","crit":["` + verifiedSignatureExt + `"],"` + verifiedSignatureExt + `":"` + tenant + `"}`
}

func TestVerifyWithVerifiedSignature(t *testing.T) {
	t.Parallel()

	trustedKey := bytes.Repeat([]byte{0x41}, 32)
	attackerKey := bytes.Repeat([]byte{0x42}, 32)
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"op":"read"}`))

	trusted := hmacSignatureEntry(t, payload, tenantProtectedHeader("tenant-a"), trustedKey)
	untrusted := hmacSignatureEntry(t, payload, tenantProtectedHeader("tenant-b"), attackerKey)

	tenantOf := func(t *testing.T, sig *jws.Signature) any {
		t.Helper()
		var v string
		require.NoError(t, sig.ProtectedHeaders().Get(verifiedSignatureExt, &v), `signature should carry %q`, verifiedSignatureExt)
		return v
	}

	t.Run("unverified entry listed first", func(t *testing.T) {
		t.Parallel()

		data, err := json.Marshal(generalJSONJWS{Payload: payload, Signatures: []signatureEntry{untrusted, trusted}})
		require.NoError(t, err, `json.Marshal should succeed`)

		var verified *jws.Signature
		msg := jws.NewMessage()
		_, err = jws.Verify(data,
			jws.WithKey(jwa.HS256(), trustedKey),
			jws.WithCritValidation(true),
			jws.WithCritExtension(verifiedSignatureExt),
			jws.WithMessage(msg),
			jws.WithVerifiedSignature(&verified),
		)
		require.NoError(t, err, `jws.Verify should succeed on the trusted entry`)
		require.NotNil(t, verified, `WithVerifiedSignature should be set`)

		require.Equal(t, "tenant-a", tenantOf(t, verified), `verified signature should be the trusted one`)
		require.Same(t, msg.Signatures()[1], verified, `verified signature should be an entry of the message`)
		require.Equal(t, "tenant-b", tenantOf(t, msg.Signatures()[0]), `entry 0 did not verify and keeps its own value`)
	})

	// Signed with the trusted key, but its "crit" lists an extension that the
	// caller did not declare with WithCritExtension.
	undeclaredCrit := hmacSignatureEntry(t, payload,
		`{"alg":"HS256","crit":["x-undeclared"],"x-undeclared":"v"}`, trustedKey)

	t.Run("validly signed entry with undeclared crit is skipped", func(t *testing.T) {
		t.Parallel()

		data, err := json.Marshal(generalJSONJWS{Payload: payload, Signatures: []signatureEntry{undeclaredCrit, trusted}})
		require.NoError(t, err, `json.Marshal should succeed`)

		var verified *jws.Signature
		msg := jws.NewMessage()
		_, err = jws.Verify(data,
			jws.WithKey(jwa.HS256(), trustedKey),
			jws.WithCritValidation(true),
			jws.WithCritExtension(verifiedSignatureExt),
			jws.WithMessage(msg),
			jws.WithVerifiedSignature(&verified),
		)
		require.NoError(t, err, `jws.Verify should succeed on the entry whose crit is declared`)
		require.Same(t, msg.Signatures()[1], verified, `the entry rejected by crit validation must not be reported`)
		require.Equal(t, "tenant-a", tenantOf(t, verified))
	})

	t.Run("only entries with undeclared crit", func(t *testing.T) {
		t.Parallel()

		data, err := json.Marshal(generalJSONJWS{Payload: payload, Signatures: []signatureEntry{undeclaredCrit}})
		require.NoError(t, err, `json.Marshal should succeed`)

		var verified *jws.Signature
		_, err = jws.Verify(data,
			jws.WithKey(jwa.HS256(), trustedKey),
			jws.WithCritValidation(true),
			jws.WithCritExtension(verifiedSignatureExt),
			jws.WithVerifiedSignature(&verified),
		)
		require.ErrorContains(t, err, `invalid "crit" header`, `jws.Verify should fail because crit validation rejects every entry`)
		require.Nil(t, verified, `WithVerifiedSignature should not be set on failure`)
	})

	t.Run("unverified entry listed last", func(t *testing.T) {
		t.Parallel()

		data, err := json.Marshal(generalJSONJWS{Payload: payload, Signatures: []signatureEntry{trusted, untrusted}})
		require.NoError(t, err, `json.Marshal should succeed`)

		var verified *jws.Signature
		_, err = jws.Verify(data,
			jws.WithKey(jwa.HS256(), trustedKey),
			jws.WithCritValidation(true),
			jws.WithCritExtension(verifiedSignatureExt),
			jws.WithVerifiedSignature(&verified),
		)
		require.NoError(t, err, `jws.Verify should succeed`)
		require.NotNil(t, verified, `WithVerifiedSignature should be set`)
		require.Equal(t, "tenant-a", tenantOf(t, verified))
	})

	t.Run("flattened JSON", func(t *testing.T) {
		t.Parallel()

		data, err := json.Marshal(flattenedJSONJWS{Payload: payload, signatureEntry: trusted})
		require.NoError(t, err, `json.Marshal should succeed`)

		var verified *jws.Signature
		msg := jws.NewMessage()
		_, err = jws.Verify(data,
			jws.WithKey(jwa.HS256(), trustedKey),
			jws.WithCritValidation(true),
			jws.WithCritExtension(verifiedSignatureExt),
			jws.WithMessage(msg),
			jws.WithVerifiedSignature(&verified),
		)
		require.NoError(t, err, `jws.Verify should succeed`)
		require.Same(t, msg.Signatures()[0], verified)
		require.Equal(t, "tenant-a", tenantOf(t, verified))
	})

	t.Run("compact", func(t *testing.T) {
		t.Parallel()

		compact := []byte(trusted.Protected + "." + payload + "." + trusted.Signature)

		var verified *jws.Signature
		_, err := jws.Verify(compact,
			jws.WithKey(jwa.HS256(), trustedKey),
			jws.WithCritValidation(true),
			jws.WithCritExtension(verifiedSignatureExt),
			jws.WithCompact(),
			jws.WithVerifiedSignature(&verified),
		)
		require.NoError(t, err, `jws.Verify should succeed`)
		require.NotNil(t, verified, `WithVerifiedSignature should be set`)
		require.Equal(t, "tenant-a", tenantOf(t, verified))
	})

	t.Run("failed verification leaves the variable untouched", func(t *testing.T) {
		t.Parallel()

		data, err := json.Marshal(generalJSONJWS{Payload: payload, Signatures: []signatureEntry{untrusted}})
		require.NoError(t, err, `json.Marshal should succeed`)

		var verified *jws.Signature
		_, err = jws.Verify(data,
			jws.WithKey(jwa.HS256(), trustedKey),
			jws.WithCritValidation(true),
			jws.WithCritExtension(verifiedSignatureExt),
			jws.WithVerifiedSignature(&verified),
		)
		require.Error(t, err, `jws.Verify should fail`)
		require.Nil(t, verified, `WithVerifiedSignature should not be set on failure`)
	})

	t.Run("detached payload reader", func(t *testing.T) {
		t.Parallel()

		body := []byte(`streamed payload`)
		signed, err := jws.Sign(nil,
			jws.WithKey(jwa.HS256(), trustedKey),
			jws.WithDetachedPayloadReader(bytes.NewReader(body)),
		)
		require.NoError(t, err, `jws.Sign should succeed`)

		var verified *jws.Signature
		_, err = jws.Verify(signed,
			jws.WithKey(jwa.HS256(), trustedKey),
			jws.WithDetachedPayloadReader(bytes.NewReader(body)),
			jws.WithVerifiedSignature(&verified),
		)
		require.NoError(t, err, `jws.Verify should succeed`)
		require.NotNil(t, verified, `WithVerifiedSignature should be set`)
		alg, ok := verified.ProtectedHeaders().Algorithm()
		require.True(t, ok, `verified signature should carry "alg"`)
		require.Equal(t, jwa.HS256(), alg)
	})
}
