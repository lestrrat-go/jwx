package jwe_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v4/cert"
	"github.com/lestrrat-go/jwx/v4/jwe"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/require"
)

// TestHeadersNilAccessorContract pins down the contract for typed
// accessors when the corresponding field has never been set: each
// accessor MUST return ok=false. This is what callers rely on to guard
// against missing-field bugs (e.g. jwe/decrypt.go HPKE checks "ek").
//
// Background: JWE-002 in .tmp/review/03-core-b-jwe.md reports that the
// generated typed accessors for byte-slice / interface fields return
// ok=true unconditionally, defeating those guards. This test exercises
// the contract for every affected accessor and is expected to FAIL
// against the broken generator output.
func TestHeadersNilAccessorContract(t *testing.T) {
	t.Run("AgreementPartyUInfo", func(t *testing.T) {
		h := jwe.NewHeaders()
		require.False(t, h.Has(jwe.AgreementPartyUInfoKey), `Has should report absent`)
		v, ok := h.AgreementPartyUInfo()
		require.False(t, ok, `accessor must return ok=false when unset`)
		require.Nil(t, v, `accessor must return nil value when unset`)
	})

	t.Run("AgreementPartyVInfo", func(t *testing.T) {
		h := jwe.NewHeaders()
		require.False(t, h.Has(jwe.AgreementPartyVInfoKey), `Has should report absent`)
		v, ok := h.AgreementPartyVInfo()
		require.False(t, ok, `accessor must return ok=false when unset`)
		require.Nil(t, v, `accessor must return nil value when unset`)
	})

	t.Run("Critical", func(t *testing.T) {
		h := jwe.NewHeaders()
		require.False(t, h.Has(jwe.CriticalKey), `Has should report absent`)
		v, ok := h.Critical()
		require.False(t, ok, `accessor must return ok=false when unset`)
		require.Nil(t, v, `accessor must return nil value when unset`)
	})

	t.Run("EncapsulatedKey", func(t *testing.T) {
		h := jwe.NewHeaders()
		require.False(t, h.Has(jwe.EncapsulatedKeyKey), `Has should report absent`)
		v, ok := h.EncapsulatedKey()
		require.False(t, ok, `accessor must return ok=false when unset`)
		require.Nil(t, v, `accessor must return nil value when unset`)
	})

	t.Run("EphemeralPublicKey", func(t *testing.T) {
		h := jwe.NewHeaders()
		require.False(t, h.Has(jwe.EphemeralPublicKeyKey), `Has should report absent`)
		v, ok := h.EphemeralPublicKey()
		require.False(t, ok, `accessor must return ok=false when unset`)
		require.Nil(t, v, `accessor must return nil value when unset`)
	})

	t.Run("JWK", func(t *testing.T) {
		h := jwe.NewHeaders()
		require.False(t, h.Has(jwe.JWKKey), `Has should report absent`)
		v, ok := h.JWK()
		require.False(t, ok, `accessor must return ok=false when unset`)
		require.Nil(t, v, `accessor must return nil value when unset`)
	})

	t.Run("PSKID", func(t *testing.T) {
		h := jwe.NewHeaders()
		require.False(t, h.Has(jwe.PSKIDKey), `Has should report absent`)
		v, ok := h.PSKID()
		require.False(t, ok, `accessor must return ok=false when unset`)
		require.Nil(t, v, `accessor must return nil value when unset`)
	})

	t.Run("X509CertChain", func(t *testing.T) {
		h := jwe.NewHeaders()
		require.False(t, h.Has(jwe.X509CertChainKey), `Has should report absent`)
		v, ok := h.X509CertChain()
		require.False(t, ok, `accessor must return ok=false when unset`)
		require.Nil(t, v, `accessor must return nil value when unset`)
	})
}

// TestHeadersNilAccessorAgreesWithGet verifies that the typed accessors
// and the generic Get() / Field() path agree when a field is not set.
// Today the typed accessors say "ok=true, value=nil" while Get() and
// Field() correctly say "not present" — an internal inconsistency that
// this test pins down.
func TestHeadersNilAccessorAgreesWithGet(t *testing.T) {
	cases := []struct {
		name string
		key  string
	}{
		{"AgreementPartyUInfo", jwe.AgreementPartyUInfoKey},
		{"AgreementPartyVInfo", jwe.AgreementPartyVInfoKey},
		{"Critical", jwe.CriticalKey},
		{"EncapsulatedKey", jwe.EncapsulatedKeyKey},
		{"EphemeralPublicKey", jwe.EphemeralPublicKeyKey},
		{"JWK", jwe.JWKKey},
		{"PSKID", jwe.PSKIDKey},
		{"X509CertChain", jwe.X509CertChainKey},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := jwe.NewHeaders()

			// Has() and Field() are the trusted source of truth.
			require.False(t, h.Has(tc.key), `Has should report absent`)
			_, fieldOk := h.Field(tc.key)
			require.False(t, fieldOk, `Field should report absent`)

			// The typed accessor must agree with Has/Get. We can't
			// dispatch on a string, so call them by name.
			var ok bool
			switch tc.key {
			case jwe.AgreementPartyUInfoKey:
				_, ok = h.AgreementPartyUInfo()
			case jwe.AgreementPartyVInfoKey:
				_, ok = h.AgreementPartyVInfo()
			case jwe.CriticalKey:
				_, ok = h.Critical()
			case jwe.EncapsulatedKeyKey:
				_, ok = h.EncapsulatedKey()
			case jwe.EphemeralPublicKeyKey:
				_, ok = h.EphemeralPublicKey()
			case jwe.JWKKey:
				_, ok = h.JWK()
			case jwe.PSKIDKey:
				_, ok = h.PSKID()
			case jwe.X509CertChainKey:
				_, ok = h.X509CertChain()
			}
			require.False(t, ok, `typed accessor must agree with Has/Get`)
		})
	}
}

// TestHeadersTypedAccessorOkWhenSet covers the positive path for the
// same accessors: after setting a value, the accessor returns ok=true
// and the original value. This guards against a future "fix" that
// over-corrects to always returning false.
func TestHeadersTypedAccessorOkWhenSet(t *testing.T) {
	t.Run("AgreementPartyUInfo", func(t *testing.T) {
		h := jwe.NewHeaders()
		want := []byte("apu")
		require.NoError(t, h.Set(jwe.AgreementPartyUInfoKey, want))
		v, ok := h.AgreementPartyUInfo()
		require.True(t, ok)
		require.Equal(t, want, v)
	})

	t.Run("AgreementPartyVInfo", func(t *testing.T) {
		h := jwe.NewHeaders()
		want := []byte("apv")
		require.NoError(t, h.Set(jwe.AgreementPartyVInfoKey, want))
		v, ok := h.AgreementPartyVInfo()
		require.True(t, ok)
		require.Equal(t, want, v)
	})

	t.Run("Critical", func(t *testing.T) {
		h := jwe.NewHeaders()
		want := []string{"x-foo"}
		require.NoError(t, h.Set(jwe.CriticalKey, want))
		v, ok := h.Critical()
		require.True(t, ok)
		require.Equal(t, want, v)
	})

	t.Run("EncapsulatedKey", func(t *testing.T) {
		h := jwe.NewHeaders()
		want := []byte("ek")
		require.NoError(t, h.Set(jwe.EncapsulatedKeyKey, want))
		v, ok := h.EncapsulatedKey()
		require.True(t, ok)
		require.Equal(t, want, v)
	})

	t.Run("PSKID", func(t *testing.T) {
		h := jwe.NewHeaders()
		want := []byte("psk-id")
		require.NoError(t, h.Set(jwe.PSKIDKey, want))
		v, ok := h.PSKID()
		require.True(t, ok)
		require.Equal(t, want, v)
	})

	t.Run("X509CertChain", func(t *testing.T) {
		h := jwe.NewHeaders()
		var chain cert.Chain
		require.NoError(t, h.Set(jwe.X509CertChainKey, &chain))
		v, ok := h.X509CertChain()
		require.True(t, ok)
		require.NotNil(t, v)
	})

	t.Run("JWK", func(t *testing.T) {
		h := jwe.NewHeaders()
		raw := []byte("0123456789abcdef")
		key, err := jwk.Import[jwk.Key](raw)
		require.NoError(t, err)
		require.NoError(t, h.Set(jwe.JWKKey, key))
		v, ok := h.JWK()
		require.True(t, ok)
		require.NotNil(t, v)
	})
}
