package jwk_test

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/require"
)

// keyKinderMock is a minimal jwk.Key that only implements KeyType() and
// KeyKind(). The embedded jwk.Key interface is nil at runtime; only
// findExporters dispatches on this mock, and the sentinel exporter
// registered in the test never touches the other Key methods.
type keyKinderMock struct {
	jwk.Key

	kty  jwa.KeyType
	kind jwk.KeyKind
}

func (m keyKinderMock) KeyType() jwa.KeyType { return m.kty }
func (m keyKinderMock) KeyKind() jwk.KeyKind { return m.kind }

func TestFindExportersCaseInsensitiveKeyKind(t *testing.T) {
	const (
		registeredIdent = jwk.KeyKind("TESTKIND:FindExporters")
		mockIdent       = jwk.KeyKind("testkind:findexporters")
	)
	mockKty := jwa.NewKeyType("Test-FindExporters")

	type sentinelType struct{ name string }
	sentinel := sentinelType{name: "sentinel"}
	require.NoError(t,
		jwk.RegisterKeyExporter(registeredIdent, jwk.KeyExportFunc(func(_ jwk.Key, _ any) (any, error) {
			return sentinel, nil
		})),
		"RegisterKeyExporter should succeed")

	got, err := jwk.Export[any](keyKinderMock{kty: mockKty, kind: mockIdent})
	require.NoError(t, err, "Export should dispatch via case-insensitive KeyKind")
	require.Equal(t, sentinel, got, "Export should return sentinel from registered exporter")
}

// recipe10RawKey exercises the MIGRATION.md Recipe 10 custom-importer
// syntax. Any change to jwk.RegisterKeyImporter's signature that breaks
// bare-literal type inference (e.g. adding a second type parameter)
// must break this test so the migration guide doesn't silently rot.
type recipe10RawKey struct{ secret []byte }

// TestMigrationRecipe10KeyImporterSyntax pins the Recipe 10 syntax shown
// in MIGRATION.md: a bare function literal with a pointer argument whose
// type parameter is inferred.
func TestMigrationRecipe10KeyImporterSyntax(t *testing.T) {
	// Intentionally mirrors MIGRATION.md Recipe 10 verbatim:
	//
	//	jwk.RegisterKeyImporter(func(src *myKeyType) (jwk.Key, error) {
	//	    // ... convert — type parameter inferred, no assertion needed
	//	})
	require.NoError(t,
		jwk.RegisterKeyImporter(func(src *recipe10RawKey) (jwk.Key, error) {
			k, err := jwk.Import[jwk.Key](src.secret)
			if err != nil {
				return nil, err
			}
			require.NoError(t, k.Set(jwk.KeyIDKey, "recipe10"))
			return k, nil
		}),
		"RegisterKeyImporter should accept Recipe 10 bare-literal form")

	key, err := jwk.Import[jwk.Key](&recipe10RawKey{secret: []byte("recipe-10-secret-material")})
	require.NoError(t, err, "Import should dispatch to the Recipe 10 importer")

	kid, ok := key.KeyID()
	require.True(t, ok, "imported key should carry the KID set by the importer")
	require.Equal(t, "recipe10", kid, "KID should match the value set by the importer")
}

// dupImporterKey is a fake raw key type used by TestRegisterKeyImporterRejectsDuplicate.
// It is intentionally package-local so it does not collide with any
// built-in importer.
type dupImporterKey struct{}

func TestRegisterKeyImporterRejectsDuplicate(t *testing.T) {
	// Importer body isn't exercised — the test only asserts that the
	// Register/Unregister bookkeeping is correct. Return a non-nil
	// error so the function doesn't look like a (nil, nil) sentinel
	// that nilnil flags.
	fn := func(dupImporterKey) (jwk.Key, error) {
		return nil, errors.New("dupImporterKey: importer body not exercised by this test")
	}

	t.Run("first registration succeeds", func(t *testing.T) {
		require.NoError(t, jwk.RegisterKeyImporter(fn))
		defer jwk.UnregisterKeyImporter[dupImporterKey]()
	})

	t.Run("duplicate registration is rejected", func(t *testing.T) {
		require.NoError(t, jwk.RegisterKeyImporter(fn))
		defer jwk.UnregisterKeyImporter[dupImporterKey]()

		err := jwk.RegisterKeyImporter(fn)
		require.Error(t, err, `second RegisterKeyImporter should error`)
		require.Contains(t, err.Error(), `already registered`,
			`error should say the type is already registered`)
	})

	t.Run("Unregister + Register allows replacement", func(t *testing.T) {
		require.NoError(t, jwk.RegisterKeyImporter(fn))
		require.True(t, jwk.UnregisterKeyImporter[dupImporterKey](),
			`UnregisterKeyImporter should report removal`)
		require.NoError(t, jwk.RegisterKeyImporter(fn),
			`RegisterKeyImporter should succeed after Unregister`)
		defer jwk.UnregisterKeyImporter[dupImporterKey]()
	})

	t.Run("Unregister on unknown type returns false", func(t *testing.T) {
		require.False(t, jwk.UnregisterKeyImporter[dupImporterKey](),
			`Unregister should return false when no importer was registered`)
	})
}

// TestRegisterKeyImporterRejectsBuiltinTypes pins that the public
// Register/Unregister APIs refuse to touch the importers jwk owns for
// stdlib raw key types. Allowing a caller to swap the *rsa.PrivateKey
// (etc.) importer would let an extension silently change how every
// downstream caller's RSA private key parses — exactly the kind of
// "registered = effective" footgun the report (JWK-001) flagged.
//
// The stub importer returns a non-nil error so the test does not
// resemble a (nil, nil) sentinel.
func TestRegisterKeyImporterRejectsBuiltinTypes(t *testing.T) {
	stubErr := errors.New("stub importer must not be invoked: built-in types are reserved")

	t.Run("RegisterKeyImporter[*rsa.PrivateKey]", func(t *testing.T) {
		err := jwk.RegisterKeyImporter(func(*rsa.PrivateKey) (jwk.Key, error) {
			return nil, stubErr
		})
		require.Error(t, err, `RegisterKeyImporter should refuse a built-in raw key type`)
		require.Contains(t, err.Error(), `built-in`,
			`error should explain that built-in importers cannot be overridden`)
		require.Contains(t, err.Error(), `*rsa.PrivateKey`,
			`error should name the rejected type`)
	})

	builtins := []struct {
		name string
		fn   func() error
	}{
		{"rsa.PrivateKey", func() error {
			return jwk.RegisterKeyImporter(func(rsa.PrivateKey) (jwk.Key, error) { return nil, stubErr })
		}},
		{"*rsa.PublicKey", func() error {
			return jwk.RegisterKeyImporter(func(*rsa.PublicKey) (jwk.Key, error) { return nil, stubErr })
		}},
		{"rsa.PublicKey", func() error {
			return jwk.RegisterKeyImporter(func(rsa.PublicKey) (jwk.Key, error) { return nil, stubErr })
		}},
		{"*ecdsa.PrivateKey", func() error {
			return jwk.RegisterKeyImporter(func(*ecdsa.PrivateKey) (jwk.Key, error) { return nil, stubErr })
		}},
		{"ecdsa.PrivateKey", func() error {
			return jwk.RegisterKeyImporter(func(ecdsa.PrivateKey) (jwk.Key, error) { return nil, stubErr })
		}},
		{"*ecdsa.PublicKey", func() error {
			return jwk.RegisterKeyImporter(func(*ecdsa.PublicKey) (jwk.Key, error) { return nil, stubErr })
		}},
		{"ecdsa.PublicKey", func() error {
			return jwk.RegisterKeyImporter(func(ecdsa.PublicKey) (jwk.Key, error) { return nil, stubErr })
		}},
		{"ed25519.PrivateKey", func() error {
			return jwk.RegisterKeyImporter(func(ed25519.PrivateKey) (jwk.Key, error) { return nil, stubErr })
		}},
		{"ed25519.PublicKey", func() error {
			return jwk.RegisterKeyImporter(func(ed25519.PublicKey) (jwk.Key, error) { return nil, stubErr })
		}},
		{"*ecdh.PrivateKey", func() error {
			return jwk.RegisterKeyImporter(func(*ecdh.PrivateKey) (jwk.Key, error) { return nil, stubErr })
		}},
		{"ecdh.PrivateKey", func() error {
			return jwk.RegisterKeyImporter(func(ecdh.PrivateKey) (jwk.Key, error) { return nil, stubErr })
		}},
		{"*ecdh.PublicKey", func() error {
			return jwk.RegisterKeyImporter(func(*ecdh.PublicKey) (jwk.Key, error) { return nil, stubErr })
		}},
		{"ecdh.PublicKey", func() error {
			return jwk.RegisterKeyImporter(func(ecdh.PublicKey) (jwk.Key, error) { return nil, stubErr })
		}},
		{"[]byte", func() error {
			return jwk.RegisterKeyImporter(func([]byte) (jwk.Key, error) { return nil, stubErr })
		}},
	}
	for _, tc := range builtins {
		t.Run("RegisterKeyImporter["+tc.name+"]", func(t *testing.T) {
			err := tc.fn()
			require.Error(t, err, `RegisterKeyImporter for %s should be refused`, tc.name)
			require.Contains(t, err.Error(), `built-in`,
				`error should explain that built-in importers cannot be overridden`)
		})
	}

	t.Run("UnregisterKeyImporter[*rsa.PrivateKey] is a silent no-op", func(t *testing.T) {
		require.False(t, jwk.UnregisterKeyImporter[*rsa.PrivateKey](),
			`UnregisterKeyImporter for a built-in must report no removal`)

		// Built-in importer must still be functional after the
		// attempted unregister: importing a real *rsa.PrivateKey should
		// continue to succeed.
		raw, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err, `rsa.GenerateKey should succeed`)
		_, err = jwk.Import[jwk.Key](raw)
		require.NoError(t, err, `built-in *rsa.PrivateKey importer must remain functional`)
	})

	t.Run("UnregisterKeyImporter[*ecdsa.PrivateKey] is a silent no-op", func(t *testing.T) {
		require.False(t, jwk.UnregisterKeyImporter[*ecdsa.PrivateKey]())

		raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		_, err = jwk.Import[jwk.Key](raw)
		require.NoError(t, err, `built-in *ecdsa.PrivateKey importer must remain functional`)
	})
}
