package jwe_test

import (
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/require"
)

// TestUnprotectedZipIgnored verifies that a "zip" (compression) header
// injected into the per-recipient/unprotected header — which the AEAD does
// not authenticate — is ignored during decryption. Only the protected
// header may control post-decryption decompression.
func TestUnprotectedZipIgnored(t *testing.T) {
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

	// The malicious unprotected zip must be IGNORED: decryption returns the
	// original plaintext rather than trying (and failing/garbling) to
	// inflate non-compressed bytes.
	decrypted, err := jwe.Decrypt(tampered, jwe.WithKey(jwa.A128KW(), key))
	require.NoError(t, err, `jwe.Decrypt should succeed and ignore unprotected zip`)
	require.Equal(t, plaintext, string(decrypted), `plaintext must be intact`)
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
