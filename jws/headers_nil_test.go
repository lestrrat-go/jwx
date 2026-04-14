package jws_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/stretchr/testify/require"
)

// A freshly constructed Headers must report ok=false on every typed
// accessor for a field that has never been set. This is a regression
// guard for the genjws generator where slice/interface accessors used
// to unconditionally return ok=true.
func TestHeaders_NilAccessorsReportNotPresent(t *testing.T) {
	t.Parallel()

	h := jws.NewHeaders()

	t.Run("Algorithm", func(t *testing.T) {
		_, ok := h.Algorithm()
		require.False(t, ok)
	})
	t.Run("ContentType", func(t *testing.T) {
		_, ok := h.ContentType()
		require.False(t, ok)
	})
	t.Run("Critical", func(t *testing.T) {
		v, ok := h.Critical()
		require.False(t, ok)
		require.Nil(t, v)
	})
	t.Run("JWK", func(t *testing.T) {
		v, ok := h.JWK()
		require.False(t, ok)
		require.Nil(t, v)
	})
	t.Run("JWKSetURL", func(t *testing.T) {
		_, ok := h.JWKSetURL()
		require.False(t, ok)
	})
	t.Run("KeyID", func(t *testing.T) {
		_, ok := h.KeyID()
		require.False(t, ok)
	})
	t.Run("Type", func(t *testing.T) {
		_, ok := h.Type()
		require.False(t, ok)
	})
	t.Run("X509CertChain", func(t *testing.T) {
		v, ok := h.X509CertChain()
		require.False(t, ok)
		require.Nil(t, v)
	})
	t.Run("X509CertThumbprint", func(t *testing.T) {
		_, ok := h.X509CertThumbprint()
		require.False(t, ok)
	})
	t.Run("X509CertThumbprintS256", func(t *testing.T) {
		_, ok := h.X509CertThumbprintS256()
		require.False(t, ok)
	})
	t.Run("X509URL", func(t *testing.T) {
		_, ok := h.X509URL()
		require.False(t, ok)
	})
}
