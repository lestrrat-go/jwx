package jws_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/lestrrat-go/jwx/v4/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/require"
)

// TestVerifyWithKeySetContainingUnsupportedKey exercises jws.Verify
// against a JWK Set that mixes a usable RSA key with an UnsupportedKey
// placeholder (issue #2263). The valid key must still verify; a JWS
// whose kid points at the placeholder must fail with a descriptive
// error naming the kid, the raw kty, and the underlying reason.
func TestVerifyWithKeySetContainingUnsupportedKey(t *testing.T) {
	const payload = "Lorem ipsum"

	// The good key: sign with it and publish its public half under "goodkid".
	goodPriv, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err)
	require.NoError(t, goodPriv.Set(jwk.KeyIDKey, "goodkid"))
	signedGood, err := jws.Sign([]byte(payload), jws.WithKey(jwa.RS256(), goodPriv))
	require.NoError(t, err)

	goodPub, err := jwk.PublicKeyOf(goodPriv)
	require.NoError(t, err)
	require.NoError(t, goodPub.Set(jwk.AlgorithmKey, jwa.RS256()))
	goodPubJSON, err := json.Marshal(goodPub)
	require.NoError(t, err)

	// A JWS whose kid points at the placeholder entry.
	badPriv, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err)
	require.NoError(t, badPriv.Set(jwk.KeyIDKey, "badkid"))
	signedBad, err := jws.Sign([]byte(payload), jws.WithKey(jwa.RS256(), badPriv))
	require.NoError(t, err)

	unknownEntry := `{"kty":"FOO","use":"sig","kid":"badkid","x":"dGVzdA"}`
	setJSON := []byte(`{"keys":[` + unknownEntry + `,` + string(goodPubJSON) + `]}`)

	set, err := jwk.Parse(setJSON)
	require.NoError(t, err)
	require.Equal(t, 2, set.Len())

	t.Run("kid matches valid key verifies", func(t *testing.T) {
		got, err := jws.Verify(signedGood, jws.WithKeySet(set))
		require.NoError(t, err)
		require.Equal(t, payload, string(got))
	})

	t.Run("kid matches placeholder yields descriptive error", func(t *testing.T) {
		_, err := jws.Verify(signedBad, jws.WithKeySet(set))
		require.Error(t, err)
		require.Contains(t, err.Error(), "badkid")
		require.Contains(t, err.Error(), "FOO")
		require.Contains(t, err.Error(), "unsupported key type")
	})
}
