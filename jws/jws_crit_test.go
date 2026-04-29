package jws_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/require"
)

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
	hdrJSON := `{"alg":"HS256","b64":false}`
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

		hdrJSON := `{"alg":"HS256","b64":false}`
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
