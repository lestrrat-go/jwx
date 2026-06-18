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
	// Construct a slice with stale, non-nil error elements occupying the full
	// backing array, then hand it to freeErrorSlice.
	const n = 4
	s := make([]error, n, n)
	for i := range s {
		s[i] = errors.New("stale error")
	}

	got := freeErrorSlice(s)

	require.Equal(t, 0, len(got), "freed slice should have length 0")
	require.Equal(t, n, cap(got), "freed slice should retain its capacity")

	// The entire backing array (up to cap) must be nil. This assertion fails
	// against a no-clear implementation (e.g. returning s[:0] without clear),
	// where the stale elements remain reachable via got[:cap(got)].
	full := got[:cap(got)]
	for i, e := range full {
		require.Nil(t, e, "backing array element %d should be cleared", i)
	}
}
