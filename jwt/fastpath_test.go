package jwt_test

import (
	"crypto/sha256"
	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/require"
)

// fakeSigner is a no-op Signer used by tests that need to exercise the
// fast-path header construction with an arbitrary algorithm name. It
// ignores the key entirely so tests can pass nil.
type fakeSigner struct{}

func (fakeSigner) Sign(_ any, payload []byte) ([]byte, error) {
	h := sha256.Sum256(payload)
	return h[:], nil
}

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
			key, err := jwk.Import[jwk.Key](priv)
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

	key, err := jwk.Import[jwk.Key](priv)
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

// A caller that registers a SignatureAlgorithm whose name contains
// JSON-special bytes must not be able to inject fields into the
// protected header through the fast path. Unlike the kid case, the
// fast path fails fast here rather than silently falling back,
// because a caller who deliberately registers such a name is
// almost certainly misconfigured.
//
// Not parallel: each subtest mutates global state via
// jws.RegisterSigner / jwa.RegisterSignatureAlgorithm.
func TestSign_UnsafeAlgNameIsRejected(t *testing.T) {
	testcases := []struct {
		name string
		alg  string
	}{
		{name: "injection via quote", alg: `ES256","x":"y`},
		{name: "backslash", alg: `RS\256`},
		{name: "control byte", alg: "RS\x01256"},
		{name: "non-ascii", alg: "RSβ256"},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			badAlg := jwa.NewSignatureAlgorithm(tc.alg)
			// Register a real signer so jws.signFast reaches the header
			// construction step instead of bailing out in jwsbb.Sign.
			require.NoError(t, jws.RegisterSigner(badAlg, fakeSigner{}))
			t.Cleanup(func() {
				jws.UnregisterSigner(badAlg)
				jwa.UnregisterSignatureAlgorithm(badAlg)
			})

			tok := jwt.New()
			_, err := jwt.Sign(tok, jwt.WithKey(badAlg, nil))
			require.Error(t, err, "sign with unsafe alg name must fail")
			require.Contains(t, err.Error(), "alg")
		})
	}
}

// Sanity check: a valid alg with JSON-safe characters still signs.
func TestSign_SafeAlgNameFastPath(t *testing.T) {
	t.Parallel()

	priv, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)
	key, err := jwk.Import[jwk.Key](priv)
	require.NoError(t, err)

	signed, err := jwt.Sign(jwt.New(), jwt.WithKey(jwa.RS256(), key))
	require.NoError(t, err)

	msg, err := jws.Parse(signed)
	require.NoError(t, err)
	sigs := msg.Signatures()
	require.Len(t, sigs, 1)
	gotAlg, ok := sigs[0].ProtectedHeaders().Algorithm()
	require.True(t, ok)
	require.Equal(t, jwa.RS256().String(), gotAlg.String())
}
