// Package pool provides tests for ByteSlicePool to ensure it behaves correctly under
// both sequential and concurrent use.
package pool_test

import (
	"bytes"
	"sync"
	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/pool"
	"github.com/stretchr/testify/require"
)

// TestByteSlicePoolSequential verifies basic Get and Put behavior of ByteSlicePool.
func TestByteSlicePoolSequential(t *testing.T) {
	bs := pool.ByteSlice()
	// First Get should provide a slice with default capacity and zero length
	b := bs.Get()
	require.Equal(t, 0, len(b), "initial slice should have length 0")
	require.GreaterOrEqual(t, cap(b), 64, "initial capacity should be at least 64")

	// Append data, then put back and get again
	b = append(b, 1, 2, 3)
	require.Equal(t, 3, len(b), "slice length after append should reflect appended items")

	bs.Put(b)

	b2 := bs.Get()
	// After Put, slice should be reset to zero length
	require.Equal(t, 0, len(b2), "slice length after Put should be reset to 0")
	require.GreaterOrEqual(t, cap(b2), 64, "capacity should remain at least 64 after reset")
}

// TestByteSlicePoolConcurrent verifies that ByteSlicePool can be used safely
// from multiple goroutines without data corruption or overlapping usage.
func TestByteSlicePoolConcurrent(t *testing.T) {
	const n = 30
	const capacity = 128 // Ensure capacity is sufficient for all goroutines
	bs := pool.ByteSlice()
	var wg sync.WaitGroup
	contents := make([]string, n)

	// Concurrently Get slices and write unique data into each
	wg.Add(n)

	for i := range n {
		go func() {
			defer wg.Done()

			b := bs.GetCapacity(capacity)
			defer bs.Put(b)
			// capacity should be sufficient
			require.GreaterOrEqual(t, cap(b), capacity, "capacity should be at least default for goroutine %d", i)
			require.Len(t, b, 0, "slice should be empty at start for goroutine %d", i)

			for range capacity {
				b = append(b, byte(i+0x21))
			}

			contents[i] = string(b) // create a copy so it doesn't get modified
		}()
	}

	wg.Wait()

	require.Len(t, contents, n, "should have collected results from all goroutines")

	for i, s := range contents {
		expected := bytes.Repeat([]byte{byte(i + 0x21)}, capacity)
		require.Equal(t, string(expected), s, "content should match for goroutine %d", i)
	}
}
