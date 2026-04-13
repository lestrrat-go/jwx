package ecdsa

import (
	"crypto/elliptic"
	"fmt"
	"sync"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
)

// TestConcurrentRegisterAndLookup is a race-detector test. It runs many
// goroutines that call the read-side lookup functions while a writer
// goroutine repeatedly calls RegisterCurve. Without RLock on the reads,
// `go test -race` flags the concurrent map access; with RLock, the test
// passes cleanly.
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
				}
			}
		})
	}

	for i := range writerEntries {
		alg := jwa.NewEllipticCurveAlgorithm(fmt.Sprintf("xcut006-test-%d", i))
		RegisterCurve(alg, elliptic.P256())
	}

	close(done)
	wg.Wait()
}
