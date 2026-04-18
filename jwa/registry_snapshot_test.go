package jwa_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/stretchr/testify/require"
)

type registryCase[T interface {
	fmt.Stringer
	comparable
}] struct {
	name       string
	newValue   func(string) T
	register   func(...T)
	unregister func(...T)
	lookup     func(string) (T, bool)
	list       func() []T
}

func TestRegistrySnapshotsStayInSync(t *testing.T) {
	testRegistrySnapshot(t, registryCase[jwa.SignatureAlgorithm]{
		name:       "SignatureAlgorithm",
		newValue:   func(name string) jwa.SignatureAlgorithm { return jwa.NewSignatureAlgorithm(name) },
		register:   jwa.RegisterSignatureAlgorithm,
		unregister: jwa.UnregisterSignatureAlgorithm,
		lookup:     jwa.LookupSignatureAlgorithm,
		list:       jwa.SignatureAlgorithms,
	})
	testRegistrySnapshot(t, registryCase[jwa.KeyEncryptionAlgorithm]{
		name:       "KeyEncryptionAlgorithm",
		newValue:   func(name string) jwa.KeyEncryptionAlgorithm { return jwa.NewKeyEncryptionAlgorithm(name) },
		register:   jwa.RegisterKeyEncryptionAlgorithm,
		unregister: jwa.UnregisterKeyEncryptionAlgorithm,
		lookup:     jwa.LookupKeyEncryptionAlgorithm,
		list:       jwa.KeyEncryptionAlgorithms,
	})
	testRegistrySnapshot(t, registryCase[jwa.ContentEncryptionAlgorithm]{
		name:       "ContentEncryptionAlgorithm",
		newValue:   func(name string) jwa.ContentEncryptionAlgorithm { return jwa.NewContentEncryptionAlgorithm(name) },
		register:   jwa.RegisterContentEncryptionAlgorithm,
		unregister: jwa.UnregisterContentEncryptionAlgorithm,
		lookup:     jwa.LookupContentEncryptionAlgorithm,
		list:       jwa.ContentEncryptionAlgorithms,
	})
	testRegistrySnapshot(t, registryCase[jwa.EllipticCurveAlgorithm]{
		name:       "EllipticCurveAlgorithm",
		newValue:   func(name string) jwa.EllipticCurveAlgorithm { return jwa.NewEllipticCurveAlgorithm(name) },
		register:   jwa.RegisterEllipticCurveAlgorithm,
		unregister: jwa.UnregisterEllipticCurveAlgorithm,
		lookup:     jwa.LookupEllipticCurveAlgorithm,
		list:       jwa.EllipticCurveAlgorithms,
	})
	testRegistrySnapshot(t, registryCase[jwa.KeyType]{
		name:       "KeyType",
		newValue:   func(name string) jwa.KeyType { return jwa.NewKeyType(name) },
		register:   jwa.RegisterKeyType,
		unregister: jwa.UnregisterKeyType,
		lookup:     jwa.LookupKeyType,
		list:       jwa.KeyTypes,
	})
	testRegistrySnapshot(t, registryCase[jwa.CompressionAlgorithm]{
		name:       "CompressionAlgorithm",
		newValue:   func(name string) jwa.CompressionAlgorithm { return jwa.NewCompressionAlgorithm(name) },
		register:   jwa.RegisterCompressionAlgorithm,
		unregister: jwa.UnregisterCompressionAlgorithm,
		lookup:     jwa.LookupCompressionAlgorithm,
		list:       jwa.CompressionAlgorithms,
	})
}

func testRegistrySnapshot[T interface {
	fmt.Stringer
	comparable
}](t *testing.T, tc registryCase[T]) {
	t.Helper()

	const workers = 8
	const rounds = 32

	for round := range rounds {
		t.Run(fmt.Sprintf("%s/round-%02d", tc.name, round), func(t *testing.T) {
			values := make([]T, workers)
			for i := range workers {
				values[i] = tc.newValue(fmt.Sprintf("%s-test-%02d-%02d", tc.name, round, i))
			}
			t.Cleanup(func() {
				tc.unregister(values...)
			})

			tc.unregister(values...)
			runConcurrentRegistryMutation(tc.register, values)
			assertRegistryState(t, tc, values, true)

			runConcurrentRegistryRemoval(tc.unregister, values)
			assertRegistryState(t, tc, values, false)
		})
	}
}

func runConcurrentRegistryMutation[T any](register func(...T), values []T) {
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(len(values))
	for _, value := range values {
		go func(value T) {
			defer wg.Done()
			<-start
			register(value)
		}(value)
	}
	close(start)
	wg.Wait()
}

func runConcurrentRegistryRemoval[T any](unregister func(...T), values []T) {
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(len(values))
	for _, value := range values {
		go func(value T) {
			defer wg.Done()
			<-start
			unregister(value)
		}(value)
	}
	close(start)
	wg.Wait()
}

func assertRegistryState[T interface {
	fmt.Stringer
	comparable
}](t *testing.T, tc registryCase[T], values []T, wantPresent bool) {
	t.Helper()

	listValues := tc.list()
	listSet := make(map[T]struct{}, len(listValues))
	for _, value := range listValues {
		listSet[value] = struct{}{}
	}

	for _, value := range values {
		got, ok := tc.lookup(value.String())
		require.Equal(t, wantPresent, ok, "%s lookup state for %q", tc.name, value)
		if wantPresent {
			require.Equal(t, value, got, "%s lookup value for %q", tc.name, value)
			_, ok = listSet[value]
			require.True(t, ok, "%s list is missing %q", tc.name, value)
			continue
		}

		_, ok = listSet[value]
		require.False(t, ok, "%s list still contains %q", tc.name, value)
	}
}
