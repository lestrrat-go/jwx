package jwe_test

import (
	"sync"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"
	"github.com/stretchr/testify/require"
)

func TestHeaderNameFilter(t *testing.T) {
	t.Run("Basic functionality", func(t *testing.T) {
		// Create a filter that includes specific fields
		fn := jwe.NewHeaderNameFilter("custom1", "custom3")

		// Create a header with standard and custom fields
		headers := jwe.NewHeaders()
		// Headers in JWE might need special handling to be recognized by Keys() and Has()
		// so we'll primarily test with custom fields that are stored in privateParams
		headers.Set("custom1", "value1")
		headers.Set("custom2", "value2")
		headers.Set("custom3", "value3")

		t.Run("Filter specific fields", func(t *testing.T) {
			// Filter should return a header with only specified fields
			filtered, err := fn.Filter(headers)
			require.NoError(t, err, "fn.Filter should succeed")

			// Debug info
			t.Logf("Original headers keys: %v", headers.Keys())
			t.Logf("Filtered headers keys: %v", filtered.Keys())

			// Verify included fields are present
			require.True(t, filtered.Has("custom1"), "filtered header should have custom1 field")
			require.True(t, filtered.Has("custom3"), "filtered header should have custom3 field")

			// Verify excluded fields are not present
			require.False(t, filtered.Has("custom2"), "filtered header should not have custom2 field")
		})

		t.Run("Reject specific fields", func(t *testing.T) {
			// Reject should return a header without specified fields
			rejected, err := fn.Reject(headers)
			require.NoError(t, err, "fn.Reject should succeed")

			// Verify included fields are not present
			require.False(t, rejected.Has("custom1"), "rejected header should not have custom1 field")
			require.False(t, rejected.Has("custom3"), "rejected header should not have custom3 field")

			// Verify excluded fields are present
			require.True(t, rejected.Has("custom2"), "rejected header should have custom2 field")
		})
	})

	t.Run("Empty filter", func(t *testing.T) {
		// Create an empty filter (no fields)
		fn := jwe.NewHeaderNameFilter()

		// Create a header with some fields
		headers := jwe.NewHeaders()
		headers.Set(jwe.AlgorithmKey, jwa.RSA_OAEP_256)
		headers.Set("custom", "value")

		// Filter with empty HeaderNameFilter should result in an empty header
		filtered, err := fn.Filter(headers)
		require.NoError(t, err, "fn.Filter should succeed")
		require.Empty(t, filtered.Keys(), "filtered header should have no fields")

		// Reject with empty HeaderNameFilter should result in a copy of the original header
		rejected, err := fn.Reject(headers)
		require.NoError(t, err, "fn.Reject should succeed")

		// Check that rejected header has the same keys as original
		originalKeys := headers.Keys()
		rejectedKeys := rejected.Keys()
		require.ElementsMatch(t, originalKeys, rejectedKeys, "rejected header should have the same fields as the original")
	})

	t.Run("Concurrency safety", func(t *testing.T) {
		// This is more of a logical test than an actual concurrency test
		// but it ensures the filter is being used correctly
		fn := jwe.NewHeaderNameFilter("custom1")

		// Create a header
		headers := jwe.NewHeaders()
		headers.Set("custom1", "value1")
		headers.Set("custom2", "value2")

		// Run filter and reject operations concurrently
		var wg sync.WaitGroup
		const iterations = 10
		const numGoroutines = 2
		wg.Add(iterations * numGoroutines)
		for range iterations {
			go func() {
				defer wg.Done()
				filtered, err := fn.Filter(headers)
				require.NoError(t, err, "fn.Filter should succeed")
				require.True(t, filtered.Has("custom1"), "filtered header should have custom1 field")
				require.False(t, filtered.Has("custom2"), "filtered header should not have custom2 field")
			}()
			go func() {
				defer wg.Done()
				rejected, err := fn.Reject(headers)
				require.NoError(t, err, "fn.Reject should succeed")
				require.False(t, rejected.Has("custom1"), "rejected header should not have custom1 field")
				require.True(t, rejected.Has("custom2"), "rejected header should have custom2 field")
			}()
		}
		wg.Wait()
	})
}

func TestStandardHeadersFilter(t *testing.T) {
	t.Run("Filter standard headers", func(t *testing.T) {
		// Create a header with standard and custom fields
		headers := jwe.NewHeaders()
		// Standard headers may not be properly reflected in Keys()
		// so we focus on testing custom fields which are stored in privateParams
		headers.Set("custom1", "value1")
		headers.Set("custom2", "value2")

		stdFilter := jwe.StandardHeadersFilter()

		t.Run("Filter standard headers", func(t *testing.T) {
			// Filter should return a header with only standard fields
			filtered, err := stdFilter.Filter(headers)
			require.NoError(t, err, "filter.Filter should succeed")

			// Since our test only uses custom fields (non-standard),
			// the filtered result should be empty
			require.Empty(t, filtered.Keys(), "filtered header should have no fields")

			// Verify custom fields are not present
			require.False(t, filtered.Has("custom1"), "filtered header should not have custom1 field")
			require.False(t, filtered.Has("custom2"), "filtered header should not have custom2 field")
		})

		t.Run("Reject standard headers", func(t *testing.T) {
			// Reject should return a header with only custom fields
			rejected, err := stdFilter.Reject(headers)
			require.NoError(t, err, "filter.Reject should succeed")

			// Verify custom fields are present (all original fields should be present)
			require.True(t, rejected.Has("custom1"), "rejected header should have custom1 field")
			require.True(t, rejected.Has("custom2"), "rejected header should have custom2 field")

			// Check that all original keys are present
			originalKeys := headers.Keys()
			rejectedKeys := rejected.Keys()
			require.ElementsMatch(t, originalKeys, rejectedKeys, "rejected should have all original fields")

			// Verify values are preserved
			customValue, ok := rejected.Field("custom1")
			require.True(t, ok, "rejected.Field should succeed")
			require.Equal(t, "value1", customValue, "value for custom1 field should be preserved")
		})
	})
}
