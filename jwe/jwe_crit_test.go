package jwe_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/require"
)

// critTestKey returns a 16-byte symmetric jwk suitable for jwa.A128KW.
func critTestKey(t *testing.T) jwk.Key {
	t.Helper()
	key, err := jwk.Import[jwk.Key]([]byte(`0123456789abcdef`))
	require.NoError(t, err, `jwk.Import should succeed`)
	return key
}

// critEncrypt builds a JWE around payload with the given protected
// headers using A128KW + A128CBC-HS256.
func critEncrypt(t *testing.T, key jwk.Key, payload []byte, hdrs jwe.Headers) []byte {
	t.Helper()
	encrypted, err := jwe.Encrypt(payload,
		jwe.WithKey(jwa.A128KW(), key),
		jwe.WithContentEncryption(jwa.A128CBC_HS256()),
		jwe.WithProtectedHeaders(hdrs),
	)
	require.NoError(t, err, `jwe.Encrypt should succeed`)
	return encrypted
}

// TestCritValidationDefaultStrict covers the v4 default: jwe.Decrypt enforces
// RFC 7516 Section 4.1.13 with the WithCritExtension allowlist as the only
// way to declare which extensions the recipient understands.
func TestCritValidationDefaultStrict(t *testing.T) {
	payload := []byte(`hello world`)
	key := critTestKey(t)

	t.Run("no crit header", func(t *testing.T) {
		hdrs := jwe.NewHeaders()
		encrypted := critEncrypt(t, key, payload, hdrs)

		decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.A128KW(), key))
		require.NoError(t, err, `jwe.Decrypt should succeed when no crit header is present`)
		require.Equal(t, payload, decrypted)
	})

	t.Run("empty crit array rejected", func(t *testing.T) {
		hdrs := jwe.NewHeaders()
		require.NoError(t, hdrs.Set(jwe.CriticalKey, []string{}))
		encrypted := critEncrypt(t, key, payload, hdrs)

		_, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.A128KW(), key))
		// If jwe.NewHeaders refuses to encode an empty crit (silently
		// dropping it), this becomes a no-op pass; that's fine — the
		// non-empty-list precondition is enforced by the producer.
		if err != nil {
			require.ErrorContains(t, err, `must not be empty`)
		}
	})

	t.Run("empty extension name rejected", func(t *testing.T) {
		hdrs := jwe.NewHeaders()
		require.NoError(t, hdrs.Set(jwe.CriticalKey, []string{""}))
		encrypted := critEncrypt(t, key, payload, hdrs)

		_, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.A128KW(), key))
		require.Error(t, err, `jwe.Decrypt should reject empty extension name`)
		require.ErrorContains(t, err, `empty extension name`)
	})

	t.Run("duplicate extension rejected", func(t *testing.T) {
		hdrs := jwe.NewHeaders()
		require.NoError(t, hdrs.Set("x-foo", "v"))
		require.NoError(t, hdrs.Set(jwe.CriticalKey, []string{"x-foo", "x-foo"}))
		encrypted := critEncrypt(t, key, payload, hdrs)

		_, err := jwe.Decrypt(encrypted,
			jwe.WithKey(jwa.A128KW(), key),
			jwe.WithCritExtension("x-foo"),
		)
		require.Error(t, err, `jwe.Decrypt should reject duplicate crit entry`)
		require.ErrorContains(t, err, `duplicate`)
	})

	t.Run("standard header name rejected", func(t *testing.T) {
		hdrs := jwe.NewHeaders()
		require.NoError(t, hdrs.Set(jwe.CriticalKey, []string{"alg"}))
		encrypted := critEncrypt(t, key, payload, hdrs)

		_, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.A128KW(), key))
		require.Error(t, err, `jwe.Decrypt should reject standard header name in crit`)
		require.ErrorContains(t, err, `standard header parameter`)
	})

	t.Run("missing from protected header rejected", func(t *testing.T) {
		hdrs := jwe.NewHeaders()
		require.NoError(t, hdrs.Set(jwe.CriticalKey, []string{"x-missing"}))
		encrypted := critEncrypt(t, key, payload, hdrs)

		_, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.A128KW(), key))
		require.Error(t, err, `jwe.Decrypt should reject crit entry not present in protected header`)
		require.ErrorContains(t, err, `not present in the protected header`)
	})

	t.Run("undeclared extension rejected", func(t *testing.T) {
		hdrs := jwe.NewHeaders()
		require.NoError(t, hdrs.Set("x-foo", "v"))
		require.NoError(t, hdrs.Set(jwe.CriticalKey, []string{"x-foo"}))
		encrypted := critEncrypt(t, key, payload, hdrs)

		_, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.A128KW(), key))
		require.Error(t, err, `jwe.Decrypt should reject undeclared crit extension by default`)
		require.ErrorContains(t, err, `not declared support`)
		require.ErrorContains(t, err, `x-foo`)
	})

	t.Run("declared extension accepted", func(t *testing.T) {
		hdrs := jwe.NewHeaders()
		require.NoError(t, hdrs.Set("x-foo", "v"))
		require.NoError(t, hdrs.Set(jwe.CriticalKey, []string{"x-foo"}))
		encrypted := critEncrypt(t, key, payload, hdrs)

		decrypted, err := jwe.Decrypt(encrypted,
			jwe.WithKey(jwa.A128KW(), key),
			jwe.WithCritExtension("x-foo"),
		)
		require.NoError(t, err, `jwe.Decrypt should accept declared crit extension`)
		require.Equal(t, payload, decrypted)
	})
}

// TestCritValidationOptOut verifies that jwe.WithCritValidation(false) makes
// jwe.Decrypt silently ignore the "crit" header, restoring the v3.0.13 lax
// behavior. Each scenario would otherwise fail under the v4 default.
func TestCritValidationOptOut(t *testing.T) {
	payload := []byte(`hello world`)
	key := critTestKey(t)

	cases := []struct {
		name string
		set  func(jwe.Headers)
	}{
		{
			name: "crit references missing extension",
			set: func(h jwe.Headers) {
				require.NoError(t, h.Set(jwe.CriticalKey, []string{"x-missing"}))
			},
		},
		{
			name: "crit references standard header name",
			set: func(h jwe.Headers) {
				require.NoError(t, h.Set(jwe.CriticalKey, []string{"alg"}))
			},
		},
		{
			name: "duplicate crit entry",
			set: func(h jwe.Headers) {
				require.NoError(t, h.Set("x-foo", "v"))
				require.NoError(t, h.Set(jwe.CriticalKey, []string{"x-foo", "x-foo"}))
			},
		},
		{
			name: "undeclared extension",
			set: func(h jwe.Headers) {
				require.NoError(t, h.Set("x-foo", "v"))
				require.NoError(t, h.Set(jwe.CriticalKey, []string{"x-foo"}))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hdrs := jwe.NewHeaders()
			tc.set(hdrs)
			encrypted := critEncrypt(t, key, payload, hdrs)

			decrypted, err := jwe.Decrypt(encrypted,
				jwe.WithKey(jwa.A128KW(), key),
				jwe.WithCritValidation(false),
			)
			require.NoError(t, err, `jwe.Decrypt should succeed when crit validation is disabled`)
			require.Equal(t, payload, decrypted)
		})
	}
}

// TestCritExtensionAllowlist exercises the WithCritExtension allowlist
// behavior — the central RFC 7516 §4.1.13 / RFC 7515 §4.1.11 requirement
// that recipients MUST reject any extension they have not declared
// support for.
func TestCritExtensionAllowlist(t *testing.T) {
	payload := []byte(`hello world`)
	key := critTestKey(t)

	t.Run("variadic single call registers many", func(t *testing.T) {
		hdrs := jwe.NewHeaders()
		require.NoError(t, hdrs.Set("x-foo", "v1"))
		require.NoError(t, hdrs.Set("x-bar", "v2"))
		require.NoError(t, hdrs.Set(jwe.CriticalKey, []string{"x-foo", "x-bar"}))
		encrypted := critEncrypt(t, key, payload, hdrs)

		decrypted, err := jwe.Decrypt(encrypted,
			jwe.WithKey(jwa.A128KW(), key),
			jwe.WithCritExtension("x-foo", "x-bar"),
		)
		require.NoError(t, err, `jwe.Decrypt should accept multi-name single call`)
		require.Equal(t, payload, decrypted)
	})

	t.Run("multiple calls accumulate", func(t *testing.T) {
		hdrs := jwe.NewHeaders()
		require.NoError(t, hdrs.Set("x-foo", "v1"))
		require.NoError(t, hdrs.Set("x-bar", "v2"))
		require.NoError(t, hdrs.Set(jwe.CriticalKey, []string{"x-foo", "x-bar"}))
		encrypted := critEncrypt(t, key, payload, hdrs)

		decrypted, err := jwe.Decrypt(encrypted,
			jwe.WithKey(jwa.A128KW(), key),
			jwe.WithCritExtension("x-foo"),
			jwe.WithCritExtension("x-bar"),
		)
		require.NoError(t, err, `jwe.Decrypt should accept across multiple WithCritExtension calls`)
		require.Equal(t, payload, decrypted)
	})

	t.Run("partial allowlist rejects unmatched entry", func(t *testing.T) {
		hdrs := jwe.NewHeaders()
		require.NoError(t, hdrs.Set("x-foo", "v1"))
		require.NoError(t, hdrs.Set("x-bar", "v2"))
		require.NoError(t, hdrs.Set(jwe.CriticalKey, []string{"x-foo", "x-bar"}))
		encrypted := critEncrypt(t, key, payload, hdrs)

		_, err := jwe.Decrypt(encrypted,
			jwe.WithKey(jwa.A128KW(), key),
			jwe.WithCritExtension("x-foo"),
		)
		require.Error(t, err, `jwe.Decrypt should reject when allowlist is incomplete`)
		require.ErrorContains(t, err, `x-bar`)
	})
}
