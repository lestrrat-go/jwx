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

	testcases := []struct {
		name string
		get  func(jws.Headers) (any, bool)
	}{
		{"Algorithm", func(h jws.Headers) (any, bool) { v, ok := h.Algorithm(); return v, ok }},
		{"ContentType", func(h jws.Headers) (any, bool) { v, ok := h.ContentType(); return v, ok }},
		{"Critical", func(h jws.Headers) (any, bool) { v, ok := h.Critical(); return v, ok }},
		{"JWK", func(h jws.Headers) (any, bool) { v, ok := h.JWK(); return v, ok }},
		{"JWKSetURL", func(h jws.Headers) (any, bool) { v, ok := h.JWKSetURL(); return v, ok }},
		{"KeyID", func(h jws.Headers) (any, bool) { v, ok := h.KeyID(); return v, ok }},
		{"Type", func(h jws.Headers) (any, bool) { v, ok := h.Type(); return v, ok }},
		{"X509CertChain", func(h jws.Headers) (any, bool) { v, ok := h.X509CertChain(); return v, ok }},
		{"X509CertThumbprint", func(h jws.Headers) (any, bool) { v, ok := h.X509CertThumbprint(); return v, ok }},
		{"X509CertThumbprintS256", func(h jws.Headers) (any, bool) { v, ok := h.X509CertThumbprintS256(); return v, ok }},
		{"X509URL", func(h jws.Headers) (any, bool) { v, ok := h.X509URL(); return v, ok }},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, ok := tc.get(jws.NewHeaders())
			require.False(t, ok)
		})
	}
}
