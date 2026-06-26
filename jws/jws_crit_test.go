package jws_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/require"
)

// nonConformantB64FalseHdrJSON is the protected header for a non-conformant
// b64=false JWS — i.e. a producer that set "b64":false without including
// "b64" in "crit" (RFC 7797 §3 violation). Used by multiple b64-related
// tests to construct hand-rolled compact JWSes that exercise the slow-path
// and fast-path refusals symmetrically.
const nonConformantB64FalseHdrJSON = `{"alg":"HS256","b64":false}`

// signWith returns a JWS-compact serialization of payload signed with key
// using HS256 and the given protected headers.
func signWith(t *testing.T, key any, payload []byte, hdrs jws.Headers) []byte {
	t.Helper()
	signed, err := jws.Sign(payload, jws.WithKey(jwa.HS256(), key, jws.WithProtectedHeaders(hdrs)))
	require.NoError(t, err, `jws.Sign should succeed`)
	return signed
}

// TestCritValidationDefaultStrict covers the v4 default: jws.Verify enforces
// RFC 7515 Section 4.1.11 with the WithCritExtension allowlist as the only
// way to declare which extensions the recipient understands.
func TestCritValidationDefaultStrict(t *testing.T) {
	payload := []byte(`hello world`)
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err, `jwxtest.GenerateSymmetricJwk should succeed`)

	t.Run("no crit header", func(t *testing.T) {
		hdrs := jws.NewHeaders()
		signed := signWith(t, key, payload, hdrs)

		_, err := jws.Verify(signed, jws.WithKey(jwa.HS256(), key))
		require.NoError(t, err, `jws.Verify should succeed when no crit header is present`)
	})

	t.Run("empty crit array rejected", func(t *testing.T) {
		hdrs := jws.NewHeaders()
		require.NoError(t, hdrs.Set(jws.CriticalKey, []string{}))
		signed := signWith(t, key, payload, hdrs)

		_, err := jws.Verify(signed, jws.WithKey(jwa.HS256(), key))
		require.Error(t, err, `jws.Verify should reject empty crit array`)
		require.ErrorContains(t, err, `must not be empty`)
	})

	t.Run("empty extension name rejected", func(t *testing.T) {
		hdrs := jws.NewHeaders()
		require.NoError(t, hdrs.Set(jws.CriticalKey, []string{""}))
		signed := signWith(t, key, payload, hdrs)

		_, err := jws.Verify(signed, jws.WithKey(jwa.HS256(), key))
		require.Error(t, err, `jws.Verify should reject empty extension name`)
		require.ErrorContains(t, err, `empty extension name`)
	})

	t.Run("duplicate extension rejected", func(t *testing.T) {
		hdrs := jws.NewHeaders()
		require.NoError(t, hdrs.Set("x-foo", "v"))
		require.NoError(t, hdrs.Set(jws.CriticalKey, []string{"x-foo", "x-foo"}))
		signed := signWith(t, key, payload, hdrs)

		_, err := jws.Verify(signed,
			jws.WithKey(jwa.HS256(), key),
			jws.WithCritExtension("x-foo"),
		)
		require.Error(t, err, `jws.Verify should reject duplicate crit entry`)
		require.ErrorContains(t, err, `duplicate`)
	})

	t.Run("standard header name rejected", func(t *testing.T) {
		hdrs := jws.NewHeaders()
		require.NoError(t, hdrs.Set(jws.CriticalKey, []string{"alg"}))
		signed := signWith(t, key, payload, hdrs)

		_, err := jws.Verify(signed, jws.WithKey(jwa.HS256(), key))
		require.Error(t, err, `jws.Verify should reject standard header name in crit`)
		require.ErrorContains(t, err, `standard header parameter`)
	})

	t.Run("missing from protected header rejected", func(t *testing.T) {
		hdrs := jws.NewHeaders()
		require.NoError(t, hdrs.Set(jws.CriticalKey, []string{"x-missing"}))
		signed := signWith(t, key, payload, hdrs)

		_, err := jws.Verify(signed, jws.WithKey(jwa.HS256(), key))
		require.Error(t, err, `jws.Verify should reject crit entry not present in protected header`)
		require.ErrorContains(t, err, `not present in the protected header`)
	})

	t.Run("undeclared extension rejected", func(t *testing.T) {
		hdrs := jws.NewHeaders()
		require.NoError(t, hdrs.Set("x-foo", "v"))
		require.NoError(t, hdrs.Set(jws.CriticalKey, []string{"x-foo"}))
		signed := signWith(t, key, payload, hdrs)

		_, err := jws.Verify(signed, jws.WithKey(jwa.HS256(), key))
		require.Error(t, err, `jws.Verify should reject undeclared crit extension by default`)
		require.ErrorContains(t, err, `not declared support`)
		require.ErrorContains(t, err, `x-foo`)
	})

	t.Run("declared extension accepted", func(t *testing.T) {
		hdrs := jws.NewHeaders()
		require.NoError(t, hdrs.Set("x-foo", "v"))
		require.NoError(t, hdrs.Set(jws.CriticalKey, []string{"x-foo"}))
		signed := signWith(t, key, payload, hdrs)

		_, err := jws.Verify(signed,
			jws.WithKey(jwa.HS256(), key),
			jws.WithCritExtension("x-foo"),
		)
		require.NoError(t, err, `jws.Verify should accept declared crit extension`)
	})
}

// TestCritValidationOptOut verifies that jws.WithCritValidation(false) makes
// jws.Verify silently ignore the "crit" header, restoring the v3.0.13 lax
// behavior. Each scenario would otherwise fail under the v4 default.
func TestCritValidationOptOut(t *testing.T) {
	payload := []byte(`hello world`)
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err, `jwxtest.GenerateSymmetricJwk should succeed`)

	cases := []struct {
		name string
		set  func(jws.Headers)
	}{
		{
			name: "crit references missing extension",
			set: func(h jws.Headers) {
				require.NoError(t, h.Set(jws.CriticalKey, []string{"x-missing"}))
			},
		},
		{
			name: "crit references standard header name",
			set: func(h jws.Headers) {
				require.NoError(t, h.Set(jws.CriticalKey, []string{"alg"}))
			},
		},
		{
			name: "empty crit array",
			set: func(h jws.Headers) {
				require.NoError(t, h.Set(jws.CriticalKey, []string{}))
			},
		},
		{
			name: "duplicate crit entry",
			set: func(h jws.Headers) {
				require.NoError(t, h.Set("x-foo", "v"))
				require.NoError(t, h.Set(jws.CriticalKey, []string{"x-foo", "x-foo"}))
			},
		},
		{
			name: "undeclared extension",
			set: func(h jws.Headers) {
				require.NoError(t, h.Set("x-foo", "v"))
				require.NoError(t, h.Set(jws.CriticalKey, []string{"x-foo"}))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hdrs := jws.NewHeaders()
			tc.set(hdrs)
			signed := signWith(t, key, payload, hdrs)

			_, err := jws.Verify(signed,
				jws.WithKey(jwa.HS256(), key),
				jws.WithCritValidation(false),
			)
			require.NoError(t, err, `jws.Verify should succeed when crit validation is disabled`)
		})
	}
}

// TestCritExtensionAllowlist exercises the WithCritExtension allowlist
// behavior — the central RFC 7515 §4.1.11 requirement that recipients
// MUST reject any extension they have not declared support for.
func TestCritExtensionAllowlist(t *testing.T) {
	payload := []byte(`hello world`)
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err, `jwxtest.GenerateSymmetricJwk should succeed`)

	t.Run("variadic single call registers many", func(t *testing.T) {
		hdrs := jws.NewHeaders()
		require.NoError(t, hdrs.Set("x-foo", "v1"))
		require.NoError(t, hdrs.Set("x-bar", "v2"))
		require.NoError(t, hdrs.Set(jws.CriticalKey, []string{"x-foo", "x-bar"}))
		signed := signWith(t, key, payload, hdrs)

		_, err := jws.Verify(signed,
			jws.WithKey(jwa.HS256(), key),
			jws.WithCritExtension("x-foo", "x-bar"),
		)
		require.NoError(t, err, `jws.Verify should accept multi-name single call`)
	})

	t.Run("multiple calls accumulate", func(t *testing.T) {
		hdrs := jws.NewHeaders()
		require.NoError(t, hdrs.Set("x-foo", "v1"))
		require.NoError(t, hdrs.Set("x-bar", "v2"))
		require.NoError(t, hdrs.Set(jws.CriticalKey, []string{"x-foo", "x-bar"}))
		signed := signWith(t, key, payload, hdrs)

		_, err := jws.Verify(signed,
			jws.WithKey(jwa.HS256(), key),
			jws.WithCritExtension("x-foo"),
			jws.WithCritExtension("x-bar"),
		)
		require.NoError(t, err, `jws.Verify should accept across multiple WithCritExtension calls`)
	})

	t.Run("partial allowlist rejects unmatched entry", func(t *testing.T) {
		hdrs := jws.NewHeaders()
		require.NoError(t, hdrs.Set("x-foo", "v1"))
		require.NoError(t, hdrs.Set("x-bar", "v2"))
		require.NoError(t, hdrs.Set(jws.CriticalKey, []string{"x-foo", "x-bar"}))
		signed := signWith(t, key, payload, hdrs)

		_, err := jws.Verify(signed,
			jws.WithKey(jwa.HS256(), key),
			jws.WithCritExtension("x-foo"),
		)
		require.Error(t, err, `jws.Verify should reject when allowlist is incomplete`)
		require.ErrorContains(t, err, `x-bar`)
	})
}

// TestCritDetachedB64AutoDeclared verifies the RFC 7797 "b64:false"
// detached-payload flow under the default-strict crit validation. The
// caller does NOT pass jws.WithCritExtension("b64") — passing
// jws.WithDetachedPayload auto-declares "b64" because that is the
// canonical pairing for b64=false and the jws package implements the
// b64=false handling natively.
func TestCritDetachedB64AutoDeclared(t *testing.T) {
	payload := []byte(`hello world`)
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err, `jwxtest.GenerateSymmetricJwk should succeed`)

	hdrs := jws.NewHeaders()
	require.NoError(t, hdrs.Set("b64", false))
	require.NoError(t, hdrs.Set(jws.CriticalKey, []string{"b64"}))

	signed, err := jws.Sign(nil,
		jws.WithKey(jwa.HS256(), key, jws.WithProtectedHeaders(hdrs)),
		jws.WithDetachedPayload(payload),
	)
	require.NoError(t, err, `jws.Sign should succeed`)

	_, err = jws.Verify(signed,
		jws.WithKey(jwa.HS256(), key),
		jws.WithDetachedPayload(payload),
	)
	require.NoError(t, err, `jws.Verify should succeed; WithDetachedPayload auto-declares "b64"`)
}

// TestSignAutoDeclaresB64InCritWhenFalse documents that jws.Sign auto-adds
// "b64" to the protected header's "crit" array whenever the caller sets
// "b64":false. RFC 7797 §3 requires producers that set b64=false to also
// list "b64" in "crit". Callers who set b64=false typically forget the
// crit declaration; the slow-path verify side rejects (as of the b64-
// without-crit conformance fix), and the fast path always rejects b64-
// bearing inputs. Auto-adding the crit entry on the producer side keeps
// well-meaning callers from emitting non-conformant streams that fail
// to interop with strict verifiers.
//
// The auto-add is idempotent: if "b64" is already in crit, it stays
// once. If the caller has crit set to other extensions, "b64" is
// appended. If the caller has not set crit at all, crit is created with
// just "b64".
func TestSignAutoDeclaresB64InCritWhenFalse(t *testing.T) {
	payload := []byte(`hello`)
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err, `jwxtest.GenerateSymmetricJwk should succeed`)

	cases := []struct {
		name        string
		preCrit     []string // nil = unset
		expectCrit  []string
		signOptions []jws.SignOption
	}{
		{
			name:       "no crit set",
			preCrit:    nil,
			expectCrit: []string{"b64"},
		},
		{
			name:       "crit already lists b64",
			preCrit:    []string{"b64"},
			expectCrit: []string{"b64"},
		},
		{
			name:       "crit lists other extensions but not b64",
			preCrit:    []string{"x-other"},
			expectCrit: []string{"x-other", "b64"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hdrs := jws.NewHeaders()
			require.NoError(t, hdrs.Set("b64", false))
			if tc.preCrit != nil {
				require.NoError(t, hdrs.Set(jws.CriticalKey, tc.preCrit))
				if len(tc.preCrit) > 0 && tc.preCrit[0] != "b64" {
					// Set a placeholder header so validateCritical
					// does not later complain that the crit name is
					// not present in the protected header.
					require.NoError(t, hdrs.Set(tc.preCrit[0], "v"))
				}
			}

			opts := append([]jws.SignOption{
				jws.WithKey(jwa.HS256(), key, jws.WithProtectedHeaders(hdrs)),
			}, tc.signOptions...)

			signed, err := jws.Sign(payload, opts...)
			require.NoError(t, err, `jws.Sign should succeed and auto-declare b64 in crit`)

			msg, err := jws.Parse(signed)
			require.NoError(t, err, `jws.Parse should succeed`)
			require.Len(t, msg.Signatures(), 1)

			gotCrit, ok := msg.Signatures()[0].ProtectedHeaders().Critical()
			require.True(t, ok, `protected header should have "crit" set`)
			require.Equal(t, tc.expectCrit, gotCrit, `crit array should match expected after auto-declare`)
		})
	}
}

// TestCritInBandB64RequiresExplicit locks the scoping rule for the b64
// auto-declaration: the auto-declare only happens when
// jws.WithDetachedPayload is passed. An in-band b64=false JWS with
// crit=["b64"] still requires the caller to declare "b64" explicitly,
// otherwise jws.Verify rejects it.
func TestCritInBandB64RequiresExplicit(t *testing.T) {
	payload := []byte(`hello`)
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err, `jwxtest.GenerateSymmetricJwk should succeed`)

	hdrs := jws.NewHeaders()
	require.NoError(t, hdrs.Set("b64", false))
	require.NoError(t, hdrs.Set(jws.CriticalKey, []string{"b64"}))

	signed, err := jws.Sign(payload,
		jws.WithKey(jwa.HS256(), key, jws.WithProtectedHeaders(hdrs)),
	)
	require.NoError(t, err, `jws.Sign should succeed`)

	_, err = jws.Verify(signed, jws.WithKey(jwa.HS256(), key))
	require.Error(t, err, `jws.Verify should reject in-band b64=false without explicit WithCritExtension("b64")`)
	require.ErrorContains(t, err, `not declared support`)

	_, err = jws.Verify(signed,
		jws.WithKey(jwa.HS256(), key),
		jws.WithCritExtension("b64"),
	)
	require.NoError(t, err, `explicit WithCritExtension("b64") should make in-band b64=false succeed`)
}

// TestVerifyCompactFastRefusesCrit documents that the fast path refuses
// crit-bearing messages with the jws.ErrCritPresent() sentinel. The fast
// path has no WithCritExtension allowlist, so it cannot enforce RFC 7515
// §4.1.11; silently accepting would violate the RFC. Callers that want
// full crit handling must use jws.Verify.
func TestVerifyCompactFastRefusesCrit(t *testing.T) {
	payload := []byte(`hello world`)
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err, `jwxtest.GenerateSymmetricJwk should succeed`)

	cases := []struct {
		name string
		set  func(jws.Headers)
	}{
		{
			name: "crit references missing extension",
			set: func(h jws.Headers) {
				require.NoError(t, h.Set(jws.CriticalKey, []string{"x-missing"}))
			},
		},
		{
			name: "crit references standard header name",
			set: func(h jws.Headers) {
				require.NoError(t, h.Set(jws.CriticalKey, []string{"alg"}))
			},
		},
		{
			name: "empty crit array",
			set: func(h jws.Headers) {
				require.NoError(t, h.Set(jws.CriticalKey, []string{}))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hdrs := jws.NewHeaders()
			tc.set(hdrs)
			signed := signWith(t, key, payload, hdrs)

			_, err := jws.VerifyCompactFast(key, signed, jwa.HS256())
			require.Error(t, err, `VerifyCompactFast must refuse crit-bearing messages`)
			require.ErrorIs(t, err, jws.ErrCritPresent(), `error should match jws.ErrCritPresent sentinel`)
		})
	}
}

// TestVerifyCompactFastRefusesB64False documents that the fast path refuses
// any protected header carrying "b64" (typically b64=false), regardless of
// whether "crit" is also present. Without this check, a non-RFC-7797-
// conformant producer that sets b64=false but omits "b64" from "crit" would
// slip past the crit refusal: the fast path's signing-input reconstruction
// (`base64(hdr).rawPayload`) coincidentally matches what such a producer
// signed, so the signature verifies, and the function would then base64-
// decode the wire payload — silently returning bytes that differ from the
// producer's intent. jws.Verify and VerifyCompactFast must agree on what
// they accept; refusing b64-bearing messages on the fast path defers them
// to jws.Verify, which has the WithDetachedPayload / WithCritExtension
// machinery to handle b64=false correctly.
func TestVerifyCompactFastRefusesB64False(t *testing.T) {
	rawKey := jwxtest.GenerateSymmetricKey()

	// Construct a non-conformant b64=false JWS WITHOUT declaring "b64" in
	// "crit" (RFC 7797 §3 requires b64 ∈ crit; a defective producer can
	// emit this anyway). Pick a payload whose raw bytes are also valid
	// base64url so the current pre-fix path would silently return wrong
	// decoded bytes rather than a base64-decode error — the worst-case
	// behavior the fix prevents.
	hdrJSON := nonConformantB64FalseHdrJSON
	hdrB64 := base64.RawURLEncoding.EncodeToString([]byte(hdrJSON))

	rawPayload := []byte("aGVsbG8") // valid base64url for "hello"
	signingInput := hdrB64 + "." + string(rawPayload)

	mac := hmac.New(sha256.New, rawKey)
	mac.Write([]byte(signingInput))
	sigB64 := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	compact := []byte(signingInput + "." + sigB64)

	_, err := jws.VerifyCompactFast(rawKey, compact, jwa.HS256())
	require.Error(t, err, `VerifyCompactFast must refuse b64-bearing messages`)
	require.ErrorIs(t, err, jws.ErrB64Present(), `error should match jws.ErrB64Present sentinel`)
}

// TestVerifyRejectsB64FalseWithoutCrit documents the slow-path mirror of
// TestVerifyCompactFastRefusesB64False. RFC 7797 §3 requires producers that
// set b64=false to also include "b64" in "crit"; §6 ties this to RFC 7515's
// critical-header-parameter rule. A defective producer can still emit a
// b64=false JWS without "b64" in crit. VerifyCompactFast rejects any b64
// header outright; jws.Verify must symmetrically reject the non-conformant
// shape (b64=false without "b64" listed in crit) so the two entry points
// agree on what they accept. Without this check, jws.Verify silently honors
// b64=false in the wire and computes its signing input differently from a
// strictly conformant verifier — exactly the cross-implementation
// disagreement RFC 7797 §6 was designed to prevent.
func TestVerifyRejectsB64FalseWithoutCrit(t *testing.T) {
	rawKey := jwxtest.GenerateSymmetricKey()

	// Construct a non-conformant compact JWS with b64=false in the
	// protected header but NO "crit" array at all. A conformant producer
	// would have set crit=["b64"]; a defective one (or an attacker
	// reaching for cross-impl interop confusion) emits this shape.
	hdrJSON := nonConformantB64FalseHdrJSON
	hdrB64 := base64.RawURLEncoding.EncodeToString([]byte(hdrJSON))

	rawPayload := []byte("hello world")
	signingInput := hdrB64 + "." + string(rawPayload)

	mac := hmac.New(sha256.New, rawKey)
	mac.Write([]byte(signingInput))
	sigB64 := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	compact := []byte(signingInput + "." + sigB64)

	_, err := jws.Verify(compact, jws.WithKey(jwa.HS256(), rawKey))
	require.Error(t, err, `jws.Verify must reject b64=false without "b64" in crit (RFC 7797 §3)`)
	require.ErrorIs(t, err, jws.VerifyError(), `b64-without-crit refusal must match jws.VerifyError() class`)
	require.ErrorContains(t, err, `b64`, `error should mention b64`)
	require.ErrorContains(t, err, `crit`, `error should mention crit`)
}

// TestVerifyCompactFastRefusalsMatchVerifyError documents that the fast-path
// refusal sentinels (ErrCritPresent, ErrB64Present) participate in the
// general jws.VerifyError() taxonomy as well as their own specific
// classifications. Code that uses errors.Is(err, jws.VerifyError()) to
// classify "is this a verify error" must succeed on these refusals — the
// refusals are returned by VerifyCompactFast and any caller that fronts the
// function with a single VerifyError() branch should not have to special-
// case them. Both classifications hold simultaneously: ErrCritPresent /
// ErrB64Present continue to identify the specific reason for the refusal.
func TestVerifyCompactFastRefusalsMatchVerifyError(t *testing.T) {
	t.Run("crit refusal", func(t *testing.T) {
		key, err := jwxtest.GenerateSymmetricJwk()
		require.NoError(t, err, `jwxtest.GenerateSymmetricJwk should succeed`)

		hdrs := jws.NewHeaders()
		require.NoError(t, hdrs.Set(jws.CriticalKey, []string{"x-test"}))
		signed := signWith(t, key, []byte("hello world"), hdrs)

		_, err = jws.VerifyCompactFast(key, signed, jwa.HS256())
		require.Error(t, err)
		require.ErrorIs(t, err, jws.ErrCritPresent(), `specific sentinel match must remain`)
		require.ErrorIs(t, err, jws.VerifyError(), `crit refusal must also match jws.VerifyError() class`)
	})

	t.Run("b64 refusal", func(t *testing.T) {
		rawKey := jwxtest.GenerateSymmetricKey()

		hdrJSON := nonConformantB64FalseHdrJSON
		hdrB64 := base64.RawURLEncoding.EncodeToString([]byte(hdrJSON))
		rawPayload := []byte("aGVsbG8")
		signingInput := hdrB64 + "." + string(rawPayload)

		mac := hmac.New(sha256.New, rawKey)
		mac.Write([]byte(signingInput))
		sigB64 := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

		compact := []byte(signingInput + "." + sigB64)

		_, err := jws.VerifyCompactFast(rawKey, compact, jwa.HS256())
		require.Error(t, err)
		require.ErrorIs(t, err, jws.ErrB64Present(), `specific sentinel match must remain`)
		require.ErrorIs(t, err, jws.VerifyError(), `b64 refusal must also match jws.VerifyError() class`)
	})
}

// signHS256Compact hand-assembles an HS256 compact JWS with an arbitrary
// protected header (JSON) over a fixed "payload", so tests can exercise
// header shapes that jws.Sign would never emit — duplicate parameters, JSON
// escapes, extra fields.
func signHS256Compact(key []byte, hdrJSON string) []byte {
	signingInput := base64.RawURLEncoding.EncodeToString([]byte(hdrJSON)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("payload"))
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return []byte(signingInput + "." + sig)
}

// TestVerifyCompactFastMinimalHeaderShape documents the fast path's
// minimal-shape gate (issue #2234). VerifyCompactFast uses fastjson, which
// keeps duplicate object members and resolves them first-wins, while
// jws.Verify uses encoding/json/v2, which rejects duplicate names. Without a
// gate the two entry points disagreed: a duplicate-"alg" header verified on
// the fast path but was rejected by jws.Verify. The fast path now only
// handles a minimal header — "alg" exactly once, an optional single
// "typ"/"kid"/"cty", no JSON escapes, nothing else — and refuses everything
// else with jws.ErrNonMinimalHeader so callers defer it to jws.Verify.
func TestVerifyCompactFastMinimalHeaderShape(t *testing.T) {
	key := jwxtest.GenerateSymmetricKey()

	t.Run("minimal shapes take the fast path", func(t *testing.T) {
		for _, hdr := range []string{
			`{"alg":"HS256"}`,
			`{"alg":"HS256","typ":"JWT"}`,
			`{"alg":"HS256","kid":"key-1"}`,
			`{"alg":"HS256","typ":"JWT","kid":"key-1"}`,
			`{"alg":"HS256","cty":"example"}`,
		} {
			t.Run(hdr, func(t *testing.T) {
				compact := signHS256Compact(key, hdr)
				payload, err := jws.VerifyCompactFast(key, compact, jwa.HS256())
				require.NoError(t, err, `minimal header must verify on the fast path`)
				require.Equal(t, []byte("payload"), payload)
			})
		}
	})

	t.Run("non-minimal shapes are refused with ErrNonMinimalHeader", func(t *testing.T) {
		for _, tc := range []struct{ name, hdr string }{
			{"duplicate alg", `{"alg":"HS256","alg":"none"}`},
			{"duplicate typ", `{"alg":"HS256","typ":"JWT","typ":"JWT"}`},
			{"unknown parameter", `{"alg":"HS256","x5t":"abc"}`},
			{"key-source parameter", `{"alg":"HS256","jwk":{"kty":"oct"}}`},
			{"nested duplicate", `{"alg":"HS256","extra":[{"a":1,"a":2}]}`},
			{"escaped key", "{\"\\u0061lg\":\"HS256\"}"},
			{"escaped duplicate", "{\"alg\":\"HS256\",\"\\u0061lg\":\"none\"}"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				compact := signHS256Compact(key, tc.hdr)
				_, err := jws.VerifyCompactFast(key, compact, jwa.HS256())
				require.Error(t, err)
				require.ErrorIs(t, err, jws.ErrNonMinimalHeader(), `specific sentinel must match`)
				require.ErrorIs(t, err, jws.VerifyError(), `refusal must also match jws.VerifyError() class`)
			})
		}
	})

	t.Run("crit and b64 are specific cases of the umbrella sentinel", func(t *testing.T) {
		// crit/b64 are specific reasons that wrap ErrNonMinimalHeader: their
		// dedicated sentinels must keep matching (callers branch on them
		// specifically), and they must ALSO match the umbrella so a single
		// ErrNonMinimalHeader check classifies every fast-path header refusal.
		critCompact := signHS256Compact(key, `{"alg":"HS256","crit":["x"]}`)
		_, err := jws.VerifyCompactFast(key, critCompact, jwa.HS256())
		require.ErrorIs(t, err, jws.ErrCritPresent(), `specific crit sentinel must match`)
		require.ErrorIs(t, err, jws.ErrNonMinimalHeader(), `crit must also match the umbrella`)
		require.NotErrorIs(t, err, jws.ErrB64Present(), `crit must not match the b64 sentinel`)

		b64Compact := signHS256Compact(key, `{"alg":"HS256","b64":true}`)
		_, err = jws.VerifyCompactFast(key, b64Compact, jwa.HS256())
		require.ErrorIs(t, err, jws.ErrB64Present(), `specific b64 sentinel must match`)
		require.ErrorIs(t, err, jws.ErrNonMinimalHeader(), `b64 must also match the umbrella`)
		require.NotErrorIs(t, err, jws.ErrCritPresent(), `b64 must not match the crit sentinel`)
	})

	t.Run("missing alg keeps the alg-specific diagnostic", func(t *testing.T) {
		// A missing "alg" is a malformed compact JWS (RFC 7515 §4.1.1), not a
		// defer-to-jws.Verify case. The gate must let the alg cross-check
		// report it so the caller still gets the specific error.
		compact := signHS256Compact(key, `{"typ":"JWT"}`)
		_, err := jws.VerifyCompactFast(key, compact, jwa.HS256())
		require.Error(t, err)
		require.NotErrorIs(t, err, jws.ErrNonMinimalHeader())
		require.ErrorContains(t, err, `"alg"`)
	})
}

// TestMessageMarshalJSONHonorsB64False documents that Message.MarshalJSON
// must NOT re-base64-encode the payload when the protected header carries
// b64=false. The parser path (UnmarshalJSON) stores raw bytes in m.payload
// for b64=false; the matching serialization in Compact() honors that flag,
// but marshalFlattened/marshalFull historically did not — a Parse →
// MarshalJSON round-trip silently produced JSON whose "payload" field
// was the raw bytes RE-base64-encoded, mismatching the protected header.
func TestMessageMarshalJSONHonorsB64False(t *testing.T) {
	rawPayload := []byte("hello world")
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err, `jwxtest.GenerateSymmetricJwk should succeed`)

	hdrs := jws.NewHeaders()
	require.NoError(t, hdrs.Set("b64", false))
	require.NoError(t, hdrs.Set(jws.CriticalKey, []string{"b64"}))
	signed, err := jws.Sign(rawPayload,
		jws.WithKey(jwa.HS256(), key, jws.WithProtectedHeaders(hdrs)))
	require.NoError(t, err, `jws.Sign with b64=false should succeed`)

	msg, err := jws.Parse(signed)
	require.NoError(t, err, `jws.Parse should succeed`)

	// Flattened form: one signature → marshalFlattened
	flatJSON, err := json.Marshal(msg)
	require.NoError(t, err, `json.Marshal of Message should succeed (flattened)`)

	var flatParsed struct {
		Payload string `json:"payload"`
	}
	require.NoError(t, json.Unmarshal(flatJSON, &flatParsed))
	require.Equal(t, string(rawPayload), flatParsed.Payload,
		`flattened-form b64=false JSON serialization must NOT re-base64-encode the payload`)

	// Round-trip: re-parsing the JSON output should produce a Message
	// whose payload bytes match the original. Without the fix, the
	// re-parsed message would store base64(rawPayload) as raw bytes
	// (because the protected header still says b64=false), corrupting
	// the producer's signing input.
	msg2, err := jws.Parse(flatJSON)
	require.NoError(t, err, `re-Parse of MarshalJSON output should succeed`)
	require.Equal(t, msg.Payload(), msg2.Payload(),
		`Parse → MarshalJSON → Parse round-trip must preserve b64=false payload bytes`)
}
