package ecdsa

import (
	"crypto/elliptic"
	"fmt"
	"math/big"
	"sync"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/stretchr/testify/require"
)

var noopValidator = PointValidatorFunc(func(_, _ *big.Int) error { return nil })

// uniqueTestCurve wraps an elliptic.Curve to give each instance a
// distinct pointer identity. RegisterCurve now rejects duplicate
// registrations of the same curve value, so tests that exercise the
// writer path need fresh curve identities per iteration. The embedded
// Curve provides all the interface methods unchanged, so behavior is
// identical to the underlying stdlib curve.
type uniqueTestCurve struct {
	elliptic.Curve
}

// TestConcurrentRegisterAndLookup is a race-detector test. It runs many
// goroutines that call the read-side lookup functions while a writer
// goroutine repeatedly calls RegisterCurve. The Algorithms path also
// iterates the returned slice so `go test -race` exercises the snapshot
// semantics rather than only the map lookups.
//
// Each writer iteration wraps elliptic.P256() in a fresh uniqueTestCurve
// pointer so it gets a distinct interface identity and passes the
// duplicate-registration guard. The stdlib P256/P384/P521 entries
// installed in init() are preserved for any subsequent tests in the
// same process.
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
		_ = RegisterCurve(alg, &uniqueTestCurve{Curve: elliptic.P256()}, noopValidator)
	}

	close(done)
	wg.Wait()
}

// TestRegisterCurveRejectsDuplicates asserts that RegisterCurve refuses
// to overwrite an existing entry keyed by either the alg or the curve.
// This is the defense-in-depth guard that prevents a late init() from
// silently replacing a built-in NIST validator with a weaker one.
//
// The test is in the internal ecdsa package, so the parent jwk package's
// init() does not run and the NIST entries are not pre-populated. The
// test establishes its own baseline by registering a fresh (alg, curve)
// pair and then asserts the second registration errors.
func TestRegisterCurveRejectsDuplicates(t *testing.T) {
	baselineAlg := jwa.NewEllipticCurveAlgorithm("dupe-test-baseline")
	baselineCurve := &uniqueTestCurve{Curve: elliptic.P256()}
	if err := RegisterCurve(baselineAlg, baselineCurve, noopValidator); err != nil {
		t.Fatalf(`baseline RegisterCurve must succeed: %v`, err)
	}

	t.Run("duplicate alg", func(t *testing.T) {
		// Re-registering baselineAlg, even with a fresh curve identity,
		// must error.
		err := RegisterCurve(baselineAlg, &uniqueTestCurve{Curve: elliptic.P256()}, noopValidator)
		if err == nil {
			t.Fatal(`RegisterCurve must refuse to re-register an existing algorithm`)
		}
	})

	t.Run("duplicate curve", func(t *testing.T) {
		// Registering baselineCurve under a brand-new alg must error
		// because the curve identity already has an owner.
		alg := jwa.NewEllipticCurveAlgorithm("dupe-test-other-alg")
		err := RegisterCurve(alg, baselineCurve, noopValidator)
		if err == nil {
			t.Fatal(`RegisterCurve must refuse to re-register an existing curve`)
		}
	})

	t.Run("nil validator", func(t *testing.T) {
		alg := jwa.NewEllipticCurveAlgorithm("dupe-test-nil-validator")
		err := RegisterCurve(alg, &uniqueTestCurve{Curve: elliptic.P256()}, nil)
		if err == nil {
			t.Fatal(`RegisterCurve must refuse a nil validator`)
		}
	})
}

func TestAlgorithmsReturnsSnapshot(t *testing.T) {
	registered := jwa.NewEllipticCurveAlgorithm("snapshot-test-registered")
	tampered := jwa.NewEllipticCurveAlgorithm("snapshot-test-tampered")

	err := RegisterCurve(registered, &uniqueTestCurve{Curve: elliptic.P256()}, noopValidator)
	require.NoError(t, err, `RegisterCurve should succeed`)

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
