package jwa_test

import (
	"errors"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/stretchr/testify/require"
)

// TestRegisterCrossKindCollision pins JWA-001: registering an
// algorithm name that is already owned by a different kind must
// return a structured error naming both kinds. Before unification,
// the three Register* functions kept independent maps and would
// happily accept the same string in two of them, after which
// KeyAlgorithmFrom would silently resolve via fixed precedence.
func TestRegisterCrossKindCollision(t *testing.T) {
	const name = "TESTALG-XKIND"

	t.Run("Sig then KeyEncryption", func(t *testing.T) {
		sig := jwa.NewSignatureAlgorithm(name)
		require.NoError(t, jwa.RegisterSignatureAlgorithm(sig))
		t.Cleanup(func() { jwa.UnregisterSignatureAlgorithm(sig) })

		kenc := jwa.NewKeyEncryptionAlgorithm(name)
		err := jwa.RegisterKeyEncryptionAlgorithm(kenc)
		require.Error(t, err, `cross-kind registration should be refused`)
		require.Contains(t, err.Error(), name, `error should name the algorithm`)
		require.Contains(t, err.Error(), "SignatureAlgorithm",
			`error should name the existing kind`)
		require.Contains(t, err.Error(), "KeyEncryptionAlgorithm",
			`error should name the requested kind`)
	})

	t.Run("Sig then ContentEncryption", func(t *testing.T) {
		// Use a distinct name so this subtest is independent of the
		// one above.
		const name = "TESTALG-XKIND-CE"
		sig := jwa.NewSignatureAlgorithm(name)
		require.NoError(t, jwa.RegisterSignatureAlgorithm(sig))
		t.Cleanup(func() { jwa.UnregisterSignatureAlgorithm(sig) })

		cenc := jwa.NewContentEncryptionAlgorithm(name)
		err := jwa.RegisterContentEncryptionAlgorithm(cenc)
		require.Error(t, err)
		require.Contains(t, err.Error(), name)
		require.Contains(t, err.Error(), "SignatureAlgorithm")
		require.Contains(t, err.Error(), "ContentEncryptionAlgorithm")
	})

	t.Run("KeyEncryption then Sig", func(t *testing.T) {
		// Inverse direction: confirm the check is symmetric.
		const name = "TESTALG-XKIND-KS"
		kenc := jwa.NewKeyEncryptionAlgorithm(name)
		require.NoError(t, jwa.RegisterKeyEncryptionAlgorithm(kenc))
		t.Cleanup(func() { jwa.UnregisterKeyEncryptionAlgorithm(kenc) })

		sig := jwa.NewSignatureAlgorithm(name)
		err := jwa.RegisterSignatureAlgorithm(sig)
		require.Error(t, err)
		require.Contains(t, err.Error(), "KeyEncryptionAlgorithm")
		require.Contains(t, err.Error(), "SignatureAlgorithm")
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
	require.NoError(t, jwa.RegisterKeyEncryptionAlgorithm(kenc))
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
// value is a no-op, regardless of whether it's a builtin. This
// preserves the pre-unification behavior; some companion init()
// paths can be re-entered in tests, and breaking idempotence here
// would surface as random test failures.
func TestRegisterIdempotent(t *testing.T) {
	require.NoError(t, jwa.RegisterSignatureAlgorithm(jwa.ES256()))
	require.NoError(t, jwa.RegisterSignatureAlgorithm(jwa.ES256()))
}
