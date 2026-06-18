package pool_test

import (
	"errors"
	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/pool"
	"github.com/stretchr/testify/require"
)

// TestErrorSlicePoolClearsBackingArray verifies that returning an error slice to
// the pool scrubs the backing array, so a later Get cannot observe stale error
// values via the capacity range (which may reference request data).
func TestErrorSlicePoolClearsBackingArray(t *testing.T) {
	p := pool.ErrorSlice()

	s := p.Get()
	require.Equal(t, 0, len(s), "initial slice should have length 0")

	s = append(s, errors.New("stale error"))
	require.Equal(t, 1, len(s), "slice length should reflect appended error")

	c := cap(s)
	p.Put(s)

	s2 := p.Get()
	require.Equal(t, 0, len(s2), "slice length after Put should be reset to 0")

	// Inspect the full backing array up to its capacity: no stale element must remain.
	full := s2[:cap(s2)]
	require.GreaterOrEqual(t, cap(s2), c, "capacity should be retained after reuse")
	for i, e := range full {
		require.Nil(t, e, "backing array element %d should be cleared", i)
	}
}
