package pool

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestFreeErrorSliceClearsBackingArray verifies that freeErrorSlice scrubs the
// entire backing array (up to cap), not just the live length. A returned slice
// may hold errors that reference request data; leaving stale non-nil elements
// reachable through the slice's capacity would keep that data alive in the
// pool's backing storage. This is a white-box test calling freeErrorSlice
// directly so it does not depend on sync.Pool returning the same backing array.
func TestFreeErrorSliceClearsBackingArray(t *testing.T) {
	// Fill the entire backing array with stale, non-nil errors, then shrink the
	// slice so len < cap. The stale elements in [1:n] now live beyond len but
	// remain reachable through the slice's capacity.
	const n = 4
	backing := make([]error, n)
	for i := range backing {
		backing[i] = errors.New("stale error")
	}
	s := backing[:1]

	got := freeErrorSlice(s)

	require.Equal(t, 0, len(got), "freed slice should have length 0")
	require.Equal(t, n, cap(got), "freed slice should retain its capacity")

	// The entire backing array (up to cap), including the region beyond the
	// original len, must be nil. This assertion fails against an implementation
	// that only clears s[:len] without first widening to cap, because the stale
	// elements in [1:n] would remain reachable via got[:cap(got)].
	full := got[:cap(got)]
	for i, e := range full {
		require.Nil(t, e, "backing array element %d should be cleared", i)
	}
}
