package jwa_test

import (
	"errors"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/stretchr/testify/require"
)

// TestRegisterCrossKindSilentNoop pins JWA-001 in v3: registering an
// algorithm name that is already owned by a different kind is a
// silent no-op (the first Register* call wins). v3's pre-existing
// Register* signature returns nothing and v3 does not change
// observable error/panic behavior, so the cross-kind path can't
// surface as a returned error or a panic — it just doesn't take.
//
// The point of this test is to pin the post-unification observable:
// after Register Sig "X" + Register KeyEnc "X", Lookup for the
// second kind returns false and KeyAlgorithmFrom resolves to the
// first kind. Pre-unification both Lookups would have returned
// their entries and KeyAlgorithmFrom would have resolved Sig-first
// by fixed precedence.
func TestRegisterCrossKindSilentNoop(t *testing.T) {
	t.Run("Sig wins, KeyEncryption registration silently dropped", func(t *testing.T) {
		const name = "TESTALG-XKIND"
		sig := jwa.NewSignatureAlgorithm(name)
		jwa.RegisterSignatureAlgorithm(sig)
		t.Cleanup(func() { jwa.UnregisterSignatureAlgorithm(sig) })

		kenc := jwa.NewKeyEncryptionAlgorithm(name)
		require.NotPanics(t, func() {
			jwa.RegisterKeyEncryptionAlgorithm(kenc)
		}, `cross-kind registration must NOT panic — v3 keeps observable error/panic behavior`)

		gotSig, ok := jwa.LookupSignatureAlgorithm(name)
		require.True(t, ok, `LookupSignatureAlgorithm should still find the first-registered Sig entry`)
		require.Equal(t, sig, gotSig)

		_, ok = jwa.LookupKeyEncryptionAlgorithm(name)
		require.False(t, ok, `LookupKeyEncryptionAlgorithm must not see the dropped second registration`)

		got, err := jwa.KeyAlgorithmFrom(name)
		require.NoError(t, err)
		_, isSig := got.(jwa.SignatureAlgorithm)
		require.True(t, isSig, `KeyAlgorithmFrom should resolve to the first-registered SignatureAlgorithm, got %T`, got)
	})

	t.Run("KeyEncryption wins, Sig registration silently dropped", func(t *testing.T) {
		// Inverse direction: confirm the silent-no-op is symmetric.
		const name = "TESTALG-XKIND-KS"
		kenc := jwa.NewKeyEncryptionAlgorithm(name)
		jwa.RegisterKeyEncryptionAlgorithm(kenc)
		t.Cleanup(func() { jwa.UnregisterKeyEncryptionAlgorithm(kenc) })

		sig := jwa.NewSignatureAlgorithm(name)
		require.NotPanics(t, func() {
			jwa.RegisterSignatureAlgorithm(sig)
		})

		_, ok := jwa.LookupSignatureAlgorithm(name)
		require.False(t, ok)

		gotKenc, ok := jwa.LookupKeyEncryptionAlgorithm(name)
		require.True(t, ok)
		require.Equal(t, kenc, gotKenc)

		got, err := jwa.KeyAlgorithmFrom(name)
		require.NoError(t, err)
		_, isKenc := got.(jwa.KeyEncryptionAlgorithm)
		require.True(t, isKenc, `KeyAlgorithmFrom should resolve to the first-registered KeyEncryptionAlgorithm, got %T`, got)
	})
}

// TestKeyAlgorithmFromUnambiguous pins that KeyAlgorithmFrom resolves
// via the shared registry, returning the registered typed value
// without any precedence rule between kinds. Before unification,
// KeyAlgorithmFrom("X") would prefer SignatureAlgorithm even when
// the caller registered "X" only as KeyEncryptionAlgorithm.
func TestKeyAlgorithmFromUnambiguous(t *testing.T) {
	const name = "TESTALG-UNAMBIG"
	kenc := jwa.NewKeyEncryptionAlgorithm(name)
	jwa.RegisterKeyEncryptionAlgorithm(kenc)
	t.Cleanup(func() { jwa.UnregisterKeyEncryptionAlgorithm(kenc) })

	got, err := jwa.KeyAlgorithmFrom(name)
	require.NoError(t, err)
	_, ok := got.(jwa.KeyEncryptionAlgorithm)
	require.True(t, ok,
		`KeyAlgorithmFrom should return the registered KeyEncryptionAlgorithm typed value, got %T`, got)
}

// TestKeyAlgorithmFromZeroValueRejected pins JWA-002: a zero-value
// typed algorithm has String() == "" and cannot resolve through any
// registry. Before this check, the typed arms accepted such inputs
// and the failure surfaced far from the call site (deep inside
// jws.Sign etc.) with confusing messages.
func TestKeyAlgorithmFromZeroValueRejected(t *testing.T) {
	t.Run("zero SignatureAlgorithm", func(t *testing.T) {
		var sa jwa.SignatureAlgorithm
		_, err := jwa.KeyAlgorithmFrom(sa)
		require.Error(t, err)
		require.True(t, errors.Is(err, jwa.ErrInvalidKeyAlgorithm()),
			`zero-value typed alg should wrap ErrInvalidKeyAlgorithm, got %v`, err)
	})

	t.Run("zero KeyEncryptionAlgorithm", func(t *testing.T) {
		var ka jwa.KeyEncryptionAlgorithm
		_, err := jwa.KeyAlgorithmFrom(ka)
		require.Error(t, err)
		require.True(t, errors.Is(err, jwa.ErrInvalidKeyAlgorithm()))
	})

	t.Run("zero ContentEncryptionAlgorithm", func(t *testing.T) {
		var ca jwa.ContentEncryptionAlgorithm
		_, err := jwa.KeyAlgorithmFrom(ca)
		require.Error(t, err)
		require.True(t, errors.Is(err, jwa.ErrInvalidKeyAlgorithm()))
	})

	t.Run("EmptySignatureAlgorithm() helper", func(t *testing.T) {
		_, err := jwa.KeyAlgorithmFrom(jwa.EmptySignatureAlgorithm())
		require.Error(t, err)
		require.True(t, errors.Is(err, jwa.ErrInvalidKeyAlgorithm()))
	})
}

// TestRegisterIdempotent pins that re-registering the exact same
// value is a no-op (no panic), regardless of whether it's a
// builtin. This preserves the pre-unification behavior; some
// extension init() paths can be re-entered in tests, and breaking
// idempotence here would surface as random failures.
func TestRegisterIdempotent(t *testing.T) {
	require.NotPanics(t, func() {
		jwa.RegisterSignatureAlgorithm(jwa.ES256())
		jwa.RegisterSignatureAlgorithm(jwa.ES256())
	})
}
