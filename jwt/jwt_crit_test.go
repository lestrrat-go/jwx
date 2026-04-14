package jwt_test

import (
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/require"
)

// signJWTWithCrit builds a JWT compact serialization whose JWS protected
// header contains the supplied extras (typically a "crit" list). Used to
// exercise the jwt-layer fast paths that previously routed through
// jws.VerifyCompactFast and silently bypassed RFC 7515 §4.1.11 crit checks.
func signJWTWithCrit(t *testing.T, key any, hdrExtras map[string]any) []byte {
	t.Helper()

	tok, err := jwt.NewBuilder().
		Issuer("https://example.com").
		Subject("crit-test").
		Build()
	require.NoError(t, err, `jwt.NewBuilder should succeed`)

	payload, err := json.Marshal(tok)
	require.NoError(t, err, `json.Marshal(tok) should succeed`)

	hdrs := jws.NewHeaders()
	for k, v := range hdrExtras {
		require.NoError(t, hdrs.Set(k, v), `jws.Headers.Set(%q)`, k)
	}

	signed, err := jws.Sign(payload, jws.WithKey(jwa.HS256(), key, jws.WithProtectedHeaders(hdrs)))
	require.NoError(t, err, `jws.Sign should succeed`)
	return signed
}

// TestParse_CritRejected_FastPath covers the canonical parseCompactFast
// route: jwt.Parse(data, jwt.WithKey(alg, key)) where the JWS carries a
// "crit" list. RFC 7515 §4.1.11 requires rejection of any unrecognized
// critical extension, and jwt.Parse must not be laxer than jws.Verify.
func TestParse_CritRejected_FastPath(t *testing.T) {
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err, `jwxtest.GenerateSymmetricJwk should succeed`)

	signed := signJWTWithCrit(t, key, map[string]any{
		"x-evil":        "pwned",
		jws.CriticalKey: []string{"x-evil"},
	})

	_, err = jwt.Parse(signed, jwt.WithKey(jwa.HS256(), key))
	require.Error(t, err, `jwt.Parse must reject unknown crit extension on the fast path`)
	require.ErrorContains(t, err, `x-evil`)
}

// TestParse_CritRejected_FastPath_SkipValidate exercises the same fast-path
// site with jwt.WithValidate(false), which still uses parseCompactFast but
// takes the skip-validate branch.
func TestParse_CritRejected_FastPath_SkipValidate(t *testing.T) {
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err, `jwxtest.GenerateSymmetricJwk should succeed`)

	signed := signJWTWithCrit(t, key, map[string]any{
		"x-evil":        "pwned",
		jws.CriticalKey: []string{"x-evil"},
	})

	_, err = jwt.Parse(signed, jwt.WithKey(jwa.HS256(), key), jwt.WithValidate(false))
	require.Error(t, err, `jwt.Parse must reject unknown crit extension on the fast path (skip-validate branch)`)
	require.ErrorContains(t, err, `x-evil`)
}

// TestParse_CritRejected_VerifyJWSShortCircuit exercises the second fast
// path at jwt/jwt.go verifyJWS (single-key short-circuit). WithPedantic is
// neither a ValidateOption nor in the tryFastPath allowlist, so it evades
// the fast path gate while leaving the converted verifyOpts list at length
// 1 — the exact shape that hits the verifyJWS short-circuit.
func TestParse_CritRejected_VerifyJWSShortCircuit(t *testing.T) {
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err, `jwxtest.GenerateSymmetricJwk should succeed`)

	signed := signJWTWithCrit(t, key, map[string]any{
		"x-evil":        "pwned",
		jws.CriticalKey: []string{"x-evil"},
	})

	_, err = jwt.Parse(signed,
		jwt.WithKey(jwa.HS256(), key),
		jwt.WithPedantic(true),
	)
	require.Error(t, err, `jwt.Parse must reject unknown crit extension at the verifyJWS short-circuit`)
	require.ErrorContains(t, err, `x-evil`)
}

// TestParse_NoCrit_FastPathUnchanged is a regression sanity check: an
// ordinary HS256 token without "crit" continues to parse successfully.
func TestParse_NoCrit_FastPathUnchanged(t *testing.T) {
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err, `jwxtest.GenerateSymmetricJwk should succeed`)

	tok, err := jwt.NewBuilder().Issuer("https://example.com").Build()
	require.NoError(t, err)

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256(), key))
	require.NoError(t, err, `jwt.Sign should succeed`)

	got, err := jwt.Parse(signed, jwt.WithKey(jwa.HS256(), key))
	require.NoError(t, err, `jwt.Parse without crit must still succeed on the fast path`)
	require.True(t, jwt.Equal(tok, got), `parsed token equals original`)
}

// TestParse_EmptyCritArray verifies that "crit":[] is rejected via the
// fall-through to jws.Verify, inheriting validateCritical's empty-list rule.
func TestParse_EmptyCritArray(t *testing.T) {
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err, `jwxtest.GenerateSymmetricJwk should succeed`)

	signed := signJWTWithCrit(t, key, map[string]any{
		jws.CriticalKey: []string{},
	})

	_, err = jwt.Parse(signed, jwt.WithKey(jwa.HS256(), key))
	require.Error(t, err, `jwt.Parse must reject empty crit array`)
	require.ErrorContains(t, err, `must not be empty`)
}

// TestParse_CritWithStandardName verifies that "crit":["alg"] is rejected
// via the fall-through, inheriting validateCritical's standard-name rule.
func TestParse_CritWithStandardName(t *testing.T) {
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err, `jwxtest.GenerateSymmetricJwk should succeed`)

	signed := signJWTWithCrit(t, key, map[string]any{
		jws.CriticalKey: []string{"alg"},
	})

	_, err = jwt.Parse(signed, jwt.WithKey(jwa.HS256(), key))
	require.Error(t, err, `jwt.Parse must reject standard header name in crit`)
	require.ErrorContains(t, err, `standard header parameter`)
}
