package jwa_test

import (
	"fmt"
	"slices"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/stretchr/testify/require"
)

type builtinRegistryCase[T interface {
	fmt.Stringer
	comparable
}] struct {
	name        string
	builtin     func() T
	replacement func(string) T
	register    func(...T)
	unregister  func(...T)
	lookup      func(string) (T, bool)
	list        func() []T
}

func TestBuiltinRegistryEntriesAreProtected(t *testing.T) {
	testBuiltinRegistryProtection(t, builtinRegistryCase[jwa.SignatureAlgorithm]{
		name:    "SignatureAlgorithm",
		builtin: jwa.RS256,
		replacement: func(name string) jwa.SignatureAlgorithm {
			return jwa.NewSignatureAlgorithm(name, jwa.WithDeprecated(true))
		},
		register:   jwa.RegisterSignatureAlgorithm,
		unregister: jwa.UnregisterSignatureAlgorithm,
		lookup:     jwa.LookupSignatureAlgorithm,
		list:       jwa.SignatureAlgorithms,
	})
	testBuiltinRegistryProtection(t, builtinRegistryCase[jwa.KeyEncryptionAlgorithm]{
		name:    "KeyEncryptionAlgorithm",
		builtin: jwa.RSA_OAEP,
		replacement: func(name string) jwa.KeyEncryptionAlgorithm {
			return jwa.NewKeyEncryptionAlgorithm(name, jwa.WithDeprecated(true))
		},
		register:   jwa.RegisterKeyEncryptionAlgorithm,
		unregister: jwa.UnregisterKeyEncryptionAlgorithm,
		lookup:     jwa.LookupKeyEncryptionAlgorithm,
		list:       jwa.KeyEncryptionAlgorithms,
	})
	testBuiltinRegistryProtection(t, builtinRegistryCase[jwa.ContentEncryptionAlgorithm]{
		name:    "ContentEncryptionAlgorithm",
		builtin: jwa.A128GCM,
		replacement: func(name string) jwa.ContentEncryptionAlgorithm {
			return jwa.NewContentEncryptionAlgorithm(name, jwa.WithDeprecated(true))
		},
		register:   jwa.RegisterContentEncryptionAlgorithm,
		unregister: jwa.UnregisterContentEncryptionAlgorithm,
		lookup:     jwa.LookupContentEncryptionAlgorithm,
		list:       jwa.ContentEncryptionAlgorithms,
	})
	testBuiltinRegistryProtection(t, builtinRegistryCase[jwa.EllipticCurveAlgorithm]{
		name:    "EllipticCurveAlgorithm",
		builtin: jwa.P256,
		replacement: func(name string) jwa.EllipticCurveAlgorithm {
			return jwa.NewEllipticCurveAlgorithm(name, jwa.WithDeprecated(true))
		},
		register:   jwa.RegisterEllipticCurveAlgorithm,
		unregister: jwa.UnregisterEllipticCurveAlgorithm,
		lookup:     jwa.LookupEllipticCurveAlgorithm,
		list:       jwa.EllipticCurveAlgorithms,
	})
	testBuiltinRegistryProtection(t, builtinRegistryCase[jwa.KeyType]{
		name:        "KeyType",
		builtin:     jwa.RSA,
		replacement: func(name string) jwa.KeyType { return jwa.NewKeyType(name, jwa.WithDeprecated(true)) },
		register:    jwa.RegisterKeyType,
		unregister:  jwa.UnregisterKeyType,
		lookup:      jwa.LookupKeyType,
		list:        jwa.KeyTypes,
	})
	testBuiltinRegistryProtection(t, builtinRegistryCase[jwa.CompressionAlgorithm]{
		name:    "CompressionAlgorithm",
		builtin: jwa.Deflate,
		replacement: func(name string) jwa.CompressionAlgorithm {
			return jwa.NewCompressionAlgorithm(name, jwa.WithDeprecated(true))
		},
		register:   jwa.RegisterCompressionAlgorithm,
		unregister: jwa.UnregisterCompressionAlgorithm,
		lookup:     jwa.LookupCompressionAlgorithm,
		list:       jwa.CompressionAlgorithms,
	})
}

func testBuiltinRegistryProtection[T interface {
	fmt.Stringer
	comparable
}](t *testing.T, tc builtinRegistryCase[T]) {
	t.Helper()

	t.Run(tc.name, func(t *testing.T) {
		orig := tc.builtin()

		tc.unregister(orig)

		got, ok := tc.lookup(orig.String())
		require.True(t, ok, "%s builtin must survive Unregister", tc.name)
		require.Equal(t, orig, got, "%s lookup should still return the builtin value", tc.name)
		assertBuiltinInList(t, tc.name, orig, tc.list())

		tc.register(orig)

		tc.register(tc.replacement(orig.String()))

		got, ok = tc.lookup(orig.String())
		require.True(t, ok, "%s builtin must still be registered", tc.name)
		require.Equal(t, orig, got, "%s lookup should still return the builtin value", tc.name)
		assertBuiltinInList(t, tc.name, orig, tc.list())
	})
}

func assertBuiltinInList[T comparable](t *testing.T, registry string, builtin T, values []T) {
	t.Helper()

	if slices.Contains(values, builtin) {
		return
	}

	require.Failf(t, "builtin missing from list", "%s list is missing %v", registry, builtin)
}
