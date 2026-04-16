package ecdsa

import (
	"crypto/elliptic"
	"fmt"
	"sync"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/stretchr/testify/require"
)

// TestConcurrentRegisterAndLookup is a race-detector test. It runs many
// goroutines that call the read-side lookup functions while a writer
// goroutine repeatedly calls RegisterCurve. The Algorithms path also
// iterates the returned slice so `go test -race` exercises the snapshot
// semantics rather than only the map lookups.
//
// The writer reuses elliptic.P256() as the curve value and registers a
// sequence of synthetic algorithm names, so the standard-curve entries
// (P256/P384/P521) installed in init() are preserved for any subsequent
// tests in the same process.
func TestConcurrentRegisterAndLookup(_ *testing.T) {
	const (
		numReaders    = 8
		writerEntries = 200
	)

	var wg sync.WaitGroup
	done := make(chan struct{})

	for range numReaders {
		wg.Go(func() {
			for {
				select {
				case <-done:
					return
				default:
					_, _ = CurveFromAlgorithm(jwa.P256())
					_, _ = AlgorithmFromCurve(elliptic.P256())
					_ = IsCurveAvailable(jwa.P256())
					for _, alg := range Algorithms() {
						_ = alg
					}
				}
			}
		})
	}

	for i := range writerEntries {
		alg := jwa.NewEllipticCurveAlgorithm(fmt.Sprintf("concurrent-register-test-%d", i))
		RegisterCurve(alg, elliptic.P256())
	}

	close(done)
	wg.Wait()
}

func TestAlgorithmsReturnsSnapshot(t *testing.T) {
	registered := jwa.NewEllipticCurveAlgorithm("snapshot-test-registered")
	tampered := jwa.NewEllipticCurveAlgorithm("snapshot-test-tampered")

	RegisterCurve(registered, elliptic.P256())

	algorithms := Algorithms()
	require.NotEmpty(t, algorithms, `Algorithms should return registered curves`)

	found := false
	for i, alg := range algorithms {
		if alg != registered {
			continue
		}

		algorithms[i] = tampered
		found = true
		break
	}
	require.True(t, found, `Algorithms snapshot should include the registered curve`)

	refreshed := Algorithms()
	require.True(t, containsAlgorithm(refreshed, registered), `registry snapshot should still contain the registered curve`)
	require.False(t, containsAlgorithm(refreshed, tampered), `mutating the returned slice must not modify the registry`)
}

func containsAlgorithm(list []jwa.EllipticCurveAlgorithm, target jwa.EllipticCurveAlgorithm) bool {
	for _, alg := range list {
		if alg == target {
			return true
		}
	}
	return false
}
