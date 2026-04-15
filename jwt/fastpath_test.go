package jwt_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v3/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/require"
)

// Regression for REV-JWT-001: a kid containing JSON-special bytes must
// not be concatenated raw into the protected header. The fast path
// should fall back to jws.Sign so encoding/json escapes the value.
func TestSign_UnsafeKidFallsBackToSlowPath(t *testing.T) {
	t.Parallel()

	priv, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)

	testcases := []struct {
		name string
		kid  string
	}{
		{name: "injection via quote+crit", kid: `a","crit":["x"],"x`},
		{name: "backslash", kid: `back\slash`},
		{name: "control byte", kid: "ctrl\x01byte"},
		{name: "non-ascii", kid: "naïve"},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			key, err := jwk.Import(priv)
			require.NoError(t, err)
			require.NoError(t, key.Set(jwk.KeyIDKey, tc.kid))

			tok := jwt.New()
			signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), key))
			require.NoError(t, err)

			msg, err := jws.Parse(signed)
			require.NoError(t, err)

			sigs := msg.Signatures()
			require.Len(t, sigs, 1)
			hdrs := sigs[0].ProtectedHeaders()

			gotKid, ok := hdrs.KeyID()
			require.True(t, ok, "kid should be present")
			require.Equal(t, tc.kid, gotKid, "kid must round-trip exactly")

			// Ensure no injected crit field from a hand-crafted kid.
			crit, _ := hdrs.Critical()
			require.Empty(t, crit, "crit must not be injected")
		})
	}
}

// Sanity check: ascii-safe kid still produces a valid token with the
// expected kid in the header (exercises the fast path itself).
func TestSign_SafeKidFastPath(t *testing.T) {
	t.Parallel()

	priv, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)

	key, err := jwk.Import(priv)
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.KeyIDKey, "safe-kid-123"))

	signed, err := jwt.Sign(jwt.New(), jwt.WithKey(jwa.RS256(), key))
	require.NoError(t, err)

	msg, err := jws.Parse(signed)
	require.NoError(t, err)
	sigs := msg.Signatures()
	require.Len(t, sigs, 1)
	gotKid, ok := sigs[0].ProtectedHeaders().KeyID()
	require.True(t, ok)
	require.Equal(t, "safe-kid-123", gotKid)
}

// Regression: a SignatureAlgorithm whose name contains JSON-special
// bytes must not be concatenated raw into the protected header via
// the fast path. jwt.Sign should fail fast with a descriptive error
// instead of emitting an injectable header.
func TestSign_UnsafeAlgRejected(t *testing.T) {
	t.Parallel()

	priv, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)

	testcases := []struct {
		name    string
		algName string
	}{
		{name: "injection via quote+crit", algName: `ES256","x":"y`},
		{name: "backslash", algName: `back\slash`},
		{name: "control byte", algName: "ctrl\x01byte"},
		{name: "non-ascii", algName: "RS256é"},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			key, err := jwk.Import(priv)
			require.NoError(t, err)

			alg := jwa.NewSignatureAlgorithm(tc.algName)
			_, err = jwt.Sign(jwt.New(), jwt.WithKey(alg, key))
			require.Error(t, err)
			require.Contains(t, err.Error(), "jwt.Sign")
			require.Contains(t, err.Error(), "algorithm")
		})
	}
}

// Sanity check: a built-in alg still signs via the fast path.
func TestSign_SafeAlgFastPath(t *testing.T) {
	t.Parallel()

	priv, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)

	key, err := jwk.Import(priv)
	require.NoError(t, err)

	signed, err := jwt.Sign(jwt.New(), jwt.WithKey(jwa.RS256(), key))
	require.NoError(t, err)

	msg, err := jws.Parse(signed)
	require.NoError(t, err)
	sigs := msg.Signatures()
	require.Len(t, sigs, 1)
	gotAlg, ok := sigs[0].ProtectedHeaders().Algorithm()
	require.True(t, ok)
	require.Equal(t, jwa.RS256(), gotAlg)
}
