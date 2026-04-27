package jwa_test

import (
	"errors"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/stretchr/testify/require"
)

// TestRegisterCrossKindCollision pins JWA-001: registering an
// algorithm name that is already owned by a different kind must
// fail loudly. Before unification, the three Register* functions
// kept independent maps and would happily accept the same string in
// two of them, after which KeyAlgorithmFrom would silently resolve
// via fixed precedence (Sig -> KeyEncryption -> ContentEncryption).
//
// v3 Register* returns nothing, so the cross-kind path panics with
// a structured message; the message must name both the existing and
// the requested kind.
func TestRegisterCrossKindCollision(t *testing.T) {
	t.Run("Sig then KeyEncryption", func(t *testing.T) {
		const name = "TESTALG-XKIND"
		sig := jwa.NewSignatureAlgorithm(name)
		jwa.RegisterSignatureAlgorithm(sig)
		t.Cleanup(func() { jwa.UnregisterSignatureAlgorithm(sig) })

		kenc := jwa.NewKeyEncryptionAlgorithm(name)
		require.PanicsWithValue(t,
			`jwa: "TESTALG-XKIND" is already registered as SignatureAlgorithm; cannot register as KeyEncryptionAlgorithm`,
			func() { jwa.RegisterKeyEncryptionAlgorithm(kenc) },
			`cross-kind registration should panic`)
	})

	t.Run("Sig then ContentEncryption", func(t *testing.T) {
		const name = "TESTALG-XKIND-CE"
		sig := jwa.NewSignatureAlgorithm(name)
		jwa.RegisterSignatureAlgorithm(sig)
		t.Cleanup(func() { jwa.UnregisterSignatureAlgorithm(sig) })

		cenc := jwa.NewContentEncryptionAlgorithm(name)
		require.PanicsWithValue(t,
			`jwa: "TESTALG-XKIND-CE" is already registered as SignatureAlgorithm; cannot register as ContentEncryptionAlgorithm`,
			func() { jwa.RegisterContentEncryptionAlgorithm(cenc) })
	})

	t.Run("KeyEncryption then Sig", func(t *testing.T) {
		// Inverse direction: confirm the check is symmetric.
		const name = "TESTALG-XKIND-KS"
		kenc := jwa.NewKeyEncryptionAlgorithm(name)
		jwa.RegisterKeyEncryptionAlgorithm(kenc)
		t.Cleanup(func() { jwa.UnregisterKeyEncryptionAlgorithm(kenc) })

		sig := jwa.NewSignatureAlgorithm(name)
		require.PanicsWithValue(t,
			`jwa: "TESTALG-XKIND-KS" is already registered as KeyEncryptionAlgorithm; cannot register as SignatureAlgorithm`,
			func() { jwa.RegisterSignatureAlgorithm(sig) })
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
// idempotence here would surface as random panics.
func TestRegisterIdempotent(t *testing.T) {
	require.NotPanics(t, func() {
		jwa.RegisterSignatureAlgorithm(jwa.ES256())
		jwa.RegisterSignatureAlgorithm(jwa.ES256())
	})
}
