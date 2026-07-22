package jws_test

import (
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v3/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/stretchr/testify/require"
)

// signedWithKID signs payload with key, stamping the protected header's
// "kid" to kid so that jws.WithKeySet can route by key ID.
func signedWithKID(t *testing.T, payload []byte, key jwk.Key, kid string) []byte {
	t.Helper()
	hdr := jws.NewHeaders()
	require.NoError(t, hdr.Set(jws.KeyIDKey, kid))

	signed, err := jws.Sign(payload, jws.WithKey(jwa.RS256(), key, jws.WithProtectedHeaders(hdr)))
	require.NoError(t, err)
	return signed
}

// TestVerifyWithUnsupportedKeyInSet checks that a JWK Set parsed with
// retention (WithStrictKeySetParsing(false)) is usable for verification:
// a signature routed to a supported key verifies, while one routed to an
// unsupported-key placeholder fails with a descriptive per-key error.
func TestVerifyWithUnsupportedKeyInSet(t *testing.T) {
	valid, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err)
	require.NoError(t, valid.Set(jwk.KeyIDKey, "rsa1"))
	require.NoError(t, valid.Set(jwk.AlgorithmKey, jwa.RS256()))
	validJSON, err := json.Marshal(valid)
	require.NoError(t, err)

	unknownEntry := []byte(`{"kty":"FOO","use":"sig","kid":"foo1","x":"dGVzdA"}`)
	setJSON := []byte(`{"keys":[` + string(unknownEntry) + `,` + string(validJSON) + `]}`)

	set, err := jwk.Parse(setJSON, jwk.WithStrictKeySetParsing(false))
	require.NoError(t, err)
	require.Equal(t, 2, set.Len())

	payload := []byte("hello world")

	t.Run("kid routes to the supported key and verifies", func(t *testing.T) {
		pub, err := valid.PublicKey()
		require.NoError(t, err)
		pubSet := jwk.NewSet()
		require.NoError(t, pubSet.AddKey(pub))

		signed := signedWithKID(t, payload, valid, "rsa1")
		got, err := jws.Verify(signed, jws.WithKeySet(pubSet))
		require.NoError(t, err)
		require.Equal(t, payload, got)
	})

	t.Run("kid routes to the placeholder and fails descriptively", func(t *testing.T) {
		// Any usable key can produce the signature; verification never
		// reaches it because the placeholder at kid "foo1" is rejected
		// first.
		signer, err := jwxtest.GenerateRsaJwk()
		require.NoError(t, err)
		signed := signedWithKID(t, payload, signer, "foo1")
		_, verr := jws.Verify(signed, jws.WithKeySet(set))
		require.Error(t, verr)
		require.Contains(t, verr.Error(), "foo1", "error should name the kid")
		require.Contains(t, verr.Error(), "FOO", "error should name the unsupported kty")
	})
}
