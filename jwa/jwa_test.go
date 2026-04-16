package jwa_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/lestrrat-go/jwx/v3/jwa"
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
	t.Run("EdDSAEd448 is not deprecated", func(t *testing.T) {
		t.Parallel()
		require.False(t, jwa.EdDSAEd448().IsDeprecated(), `EdDSAEd448 should not be deprecated`)
	})
	t.Run("EdDSAEd25519 string value", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "Ed25519", jwa.EdDSAEd25519().String(), `EdDSAEd25519 should have string value Ed25519`)
	})
	t.Run("EdDSAEd448 string value", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "Ed448", jwa.EdDSAEd448().String(), `EdDSAEd448 should have string value Ed448`)
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

	t.Run("invalid type preserves type information", func(t *testing.T) {
		t.Parallel()

		_, err := jwa.KeyAlgorithmFrom(123)
		require.Error(t, err, `creating key algorithm should fail`)
		require.True(t, errors.Is(err, jwa.ErrInvalidKeyAlgorithm()), `creating key algorithm should wrap ErrInvalidKeyAlgorithm`)
		require.Contains(t, err.Error(), fmt.Sprintf(`invalid key type: %T`, 123), `error should report invalid type`)
	})
}
