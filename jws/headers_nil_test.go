package jws_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v4/cert"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/require"
)

// TestHeadersNilAccessorContract pins the contract for typed accessors
// when the corresponding field has never been set: each accessor MUST
// return ok=false. v4 jws regressed from v3's correct behavior at the
// same time v4 jwe did (see JWE-002 in the v4 review). The generator
// fix for jwe also corrects jws — these tests guard against future
// regressions.
func TestHeadersNilAccessorContract(t *testing.T) {
	t.Run("Critical", func(t *testing.T) {
		h := jws.NewHeaders()
		require.False(t, h.Has(jws.CriticalKey))
		v, ok := h.Critical()
		require.False(t, ok, `accessor must return ok=false when unset`)
		require.Nil(t, v)
	})

	t.Run("JWK", func(t *testing.T) {
		h := jws.NewHeaders()
		require.False(t, h.Has(jws.JWKKey))
		v, ok := h.JWK()
		require.False(t, ok, `accessor must return ok=false when unset`)
		require.Nil(t, v)
	})

	t.Run("X509CertChain", func(t *testing.T) {
		h := jws.NewHeaders()
		require.False(t, h.Has(jws.X509CertChainKey))
		v, ok := h.X509CertChain()
		require.False(t, ok, `accessor must return ok=false when unset`)
		require.Nil(t, v)
	})
}

// TestHeadersTypedAccessorOkWhenSet covers the positive path so a
// future "fix" can't over-correct to always returning false.
func TestHeadersTypedAccessorOkWhenSet(t *testing.T) {
	t.Run("Critical", func(t *testing.T) {
		h := jws.NewHeaders()
		want := []string{"x-foo"}
		require.NoError(t, h.Set(jws.CriticalKey, want))
		v, ok := h.Critical()
		require.True(t, ok)
		require.Equal(t, want, v)
	})

	t.Run("JWK", func(t *testing.T) {
		h := jws.NewHeaders()
		key, err := jwk.Import[jwk.Key]([]byte("0123456789abcdef"))
		require.NoError(t, err)
		require.NoError(t, h.Set(jws.JWKKey, key))
		v, ok := h.JWK()
		require.True(t, ok)
		require.NotNil(t, v)
	})

	t.Run("X509CertChain", func(t *testing.T) {
		h := jws.NewHeaders()
		var chain cert.Chain
		require.NoError(t, h.Set(jws.X509CertChainKey, &chain))
		v, ok := h.X509CertChain()
		require.True(t, ok)
		require.NotNil(t, v)
	})
}
