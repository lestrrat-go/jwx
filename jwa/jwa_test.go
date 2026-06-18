package jwa_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/stretchr/testify/require"
)

func TestSanity(t *testing.T) {
	var k1 jwa.KeyAlgorithm = jwa.RS256()
	_, ok := k1.(jwa.SignatureAlgorithm)
	require.True(t, ok, `converting k1 to jws.SignatureAlgorithm should succeed`)
	_, ok = k1.(jwa.KeyEncryptionAlgorithm)
	require.False(t, ok, `converting k1 to jws.KeyEncryptionAlgorithm should fail`)

	var k2 jwa.KeyAlgorithm = jwa.DIRECT()
	_, ok = k2.(jwa.SignatureAlgorithm)
	require.False(t, ok, `converting k2 to jws.SignatureAlgorithm should fail`)
	_, ok = k2.(jwa.KeyEncryptionAlgorithm)
	require.True(t, ok, `converting k2 to jws.KeyEncryptionAlgorithm should succeed`)
}

func TestRFC9864(t *testing.T) {
	t.Parallel()

	t.Run("EdDSA is deprecated", func(t *testing.T) {
		t.Parallel()
		require.True(t, jwa.EdDSA().IsDeprecated(), `EdDSA should be deprecated`)
	})
	t.Run("EdDSAEd25519 is not deprecated", func(t *testing.T) {
		t.Parallel()
		require.False(t, jwa.EdDSAEd25519().IsDeprecated(), `EdDSAEd25519 should not be deprecated`)
	})
	// EdDSAEd448 tests moved to ext/ed448
	t.Run("EdDSAEd25519 string value", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "Ed25519", jwa.EdDSAEd25519().String(), `EdDSAEd25519 should have string value Ed25519`)
	})
	t.Run("LookupSignatureAlgorithm for Ed25519", func(t *testing.T) {
		t.Parallel()
		v, ok := jwa.LookupSignatureAlgorithm("Ed25519")
		require.True(t, ok, `LookupSignatureAlgorithm("Ed25519") should succeed`)
		require.Equal(t, jwa.EdDSAEd25519(), v)
	})
	t.Run("LookupEllipticCurveAlgorithm for Ed25519 still works", func(t *testing.T) {
		t.Parallel()
		v, ok := jwa.LookupEllipticCurveAlgorithm("Ed25519")
		require.True(t, ok, `LookupEllipticCurveAlgorithm("Ed25519") should still succeed`)
		require.Equal(t, jwa.Ed25519(), v)
	})
}

func TestKeyAlgorithmFrom(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		Name     string
		Input    any
		Expected jwa.KeyAlgorithm
		Error    bool
	}{
		{
			Name:     "signature algorithm",
			Input:    jwa.RS256(),
			Expected: jwa.RS256(),
		},
		{
			Name:     "key encryption algorithm",
			Input:    jwa.DIRECT(),
			Expected: jwa.DIRECT(),
		},
		{
			Name:     "content encryption algorithm",
			Input:    jwa.A128CBC_HS256(),
			Expected: jwa.A128CBC_HS256(),
		},
		{
			Name:     "valid string",
			Input:    "RS256",
			Expected: jwa.RS256(),
		},
		{
			Name:  "invalid short string",
			Input: "dummy",
			Error: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			alg, err := jwa.KeyAlgorithmFrom(tc.Input)
			if tc.Error {
				require.Error(t, err, `creating key alrgorithm should fail`)
				require.True(t, errors.Is(err, jwa.ErrInvalidKeyAlgorithm()), `creating key algorithm should wrap ErrInvalidKeyAlgorithm`)
				require.Contains(t, err.Error(), `invalid key value: "dummy"`, `short invalid input should still be rendered in full`)
			} else {
				require.NoError(t, err, `creating key alrgorithm should succeed`)
				require.Equal(t, tc.Expected, alg, `key should be valid`)
			}
		})
	}

	t.Run("invalid long string is truncated", func(t *testing.T) {
		t.Parallel()

		input := strings.Repeat("a", 80)
		_, err := jwa.KeyAlgorithmFrom(input)
		require.Error(t, err, `creating key algorithm should fail`)
		require.True(t, errors.Is(err, jwa.ErrInvalidKeyAlgorithm()), `creating key algorithm should wrap ErrInvalidKeyAlgorithm`)
		require.Contains(t, err.Error(), `invalid key value: `, `error should contain stable prefix`)
		require.Contains(t, err.Error(), strings.Repeat("a", 64)+`...`, `error should contain truncated preview`)
		require.NotContains(t, err.Error(), input, `error should not echo the full invalid value`)
	})

	t.Run("invalid multibyte string is truncated on rune boundaries", func(t *testing.T) {
		t.Parallel()

		input := strings.Repeat("あ", 80)
		_, err := jwa.KeyAlgorithmFrom(input)
		require.Error(t, err, `creating key algorithm should fail`)
		require.True(t, errors.Is(err, jwa.ErrInvalidKeyAlgorithm()), `creating key algorithm should wrap ErrInvalidKeyAlgorithm`)
		require.True(t, utf8.ValidString(err.Error()), `error should remain valid UTF-8`)
		require.Contains(t, err.Error(), strings.Repeat("あ", 64)+`...`, `error should truncate by rune count`)
		require.NotContains(t, err.Error(), input, `error should not echo the full invalid value`)
	})

	// Pin the exact error string for several input lengths so that the
	// bounded-allocation preview formatting stays byte-for-byte identical
	// to the naive []rune(v) implementation.
	t.Run("exact error string is identical regardless of length", func(t *testing.T) {
		t.Parallel()

		for _, tc := range []struct {
			Name     string
			Input    string
			Expected string
		}{
			{
				Name:     "short ASCII rendered in full",
				Input:    "dummy",
				Expected: `invalid key value: "dummy": invalid key algorithm`,
			},
			{
				Name:     "exactly the preview length rendered in full",
				Input:    strings.Repeat("a", 64),
				Expected: fmt.Sprintf(`invalid key value: %q: invalid key algorithm`, strings.Repeat("a", 64)),
			},
			{
				Name:     "one rune over the preview length is truncated",
				Input:    strings.Repeat("a", 65),
				Expected: fmt.Sprintf(`invalid key value: %q: invalid key algorithm`, strings.Repeat("a", 64)+`...`),
			},
			{
				Name:     "long ASCII is truncated",
				Input:    strings.Repeat("a", 1024),
				Expected: fmt.Sprintf(`invalid key value: %q: invalid key algorithm`, strings.Repeat("a", 64)+`...`),
			},
			{
				Name:     "long multibyte is truncated on rune boundaries",
				Input:    strings.Repeat("あ", 1024),
				Expected: fmt.Sprintf(`invalid key value: %q: invalid key algorithm`, strings.Repeat("あ", 64)+`...`),
			},
			{
				// Invalid UTF-8 bytes within the preview window must be
				// decoded to U+FFFD before %q quoting, matching the old
				// string([]rune(v)[:64]) reference. The leading "\xff\xfe"
				// are two invalid bytes that decode to two U+FFFD runes.
				Name:  "invalid utf-8 before cutoff is decoded to replacement runes",
				Input: "\xff\xfe" + strings.Repeat("a", 80),
				Expected: fmt.Sprintf(
					`invalid key value: %q: invalid key algorithm`,
					string([]rune("\xff\xfe"+strings.Repeat("a", 80))[:64])+`...`,
				),
			},
		} {
			t.Run(tc.Name, func(t *testing.T) {
				t.Parallel()
				_, err := jwa.KeyAlgorithmFrom(tc.Input)
				require.Error(t, err, `creating key algorithm should fail`)
				require.Equal(t, tc.Expected, err.Error(), `error string must be byte-for-byte identical`)
			})
		}
	})

	t.Run("invalid type preserves type information", func(t *testing.T) {
		t.Parallel()

		_, err := jwa.KeyAlgorithmFrom(123)
		require.Error(t, err, `creating key algorithm should fail`)
		require.True(t, errors.Is(err, jwa.ErrInvalidKeyAlgorithm()), `creating key algorithm should wrap ErrInvalidKeyAlgorithm`)
		require.Contains(t, err.Error(), fmt.Sprintf(`invalid key type: %T`, 123), `error should report invalid type`)
	})
}
