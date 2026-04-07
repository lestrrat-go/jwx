package jwk_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/require"
)

func TestFieldNameFilter(t *testing.T) {
	t.Run("NewFieldNameFilter", func(t *testing.T) {
		fn := jwk.NewFieldNameFilter("a", "b", "c")
		require.NotNil(t, fn, "NewFieldNameFilter should return a non-nil value")
	})

	t.Run("Filter", func(t *testing.T) {
		// Create a FieldNameFilter with field names a, b, c
		fn := jwk.NewFieldNameFilter("a", "b", "c")

		// Create a key with fields kty, a, b, c, d, e
		const src = `{
			"kty": "oct",
			"k": "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
			"a": "value_a",
			"b": "value_b",
			"c": "value_c", 
			"d": "value_d",
			"e": "value_e"
		}`

		rawKey, err := jwk.ParseKey[jwk.Key]([]byte(src))
		require.NoError(t, err, "jwk.ParseKey should succeed")

		// Filter should return a key with only fields kty, a, b, c
		filtered, err := fn.Filter(rawKey)
		require.NoError(t, err, "fn.Filter should succeed")

		// Debug: print keys for inspection
		t.Logf("Original keys: %v", rawKey.Keys())
		t.Logf("Filtered keys: %v", filtered.Keys())

		// Check that filtered key contains kty, a, b, c by examining Keys()
		filteredKeys := filtered.Keys()
		require.Contains(t, filteredKeys, jwk.KeyTypeKey, "filtered key must have kty field")
		require.Contains(t, filteredKeys, "a", "filtered key should have field 'a'")
		require.Contains(t, filteredKeys, "b", "filtered key should have field 'b'")
		require.Contains(t, filteredKeys, "c", "filtered key should have field 'c'")
		require.NotContains(t, filteredKeys, "d", "filtered key should not have field 'd'")
		require.NotContains(t, filteredKeys, "e", "filtered key should not have field 'e'")
		require.True(t, filtered.Has("a"), "filtered key should have field 'a'")
		require.True(t, filtered.Has("b"), "filtered key should have field 'b'")
		require.True(t, filtered.Has("c"), "filtered key should have field 'c'")
		require.False(t, filtered.Has("d"), "filtered key should not have field 'd'")
		require.False(t, filtered.Has("e"), "filtered key should not have field 'e'")

		// Verify values are preserved
		val, ok := filtered.Field("a")
		require.True(t, ok, "filtered.Field should succeed")
		require.Equal(t, "value_a", val, "value for field 'a' should be preserved")
	})

	t.Run("Reject", func(t *testing.T) {
		// Create a FieldNameFilter with field names a, b, c
		fn := jwk.NewFieldNameFilter("a", "b", "c")

		// Create a key with fields kty, a, b, c, d, e
		const src = `{
			"kty": "oct",
			"k": "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
			"a": "value_a",
			"b": "value_b",
			"c": "value_c", 
			"d": "value_d",
			"e": "value_e"
		}`

		rawKey, err := jwk.ParseKey[jwk.Key]([]byte(src))
		require.NoError(t, err, "jwk.ParseKey should succeed")

		// Reject should return a key with only fields kty, d, e
		rejected, err := fn.Reject(rawKey)
		require.NoError(t, err, "fn.Reject should succeed")

		// Debug: print keys for inspection
		t.Logf("Original keys: %v", rawKey.Keys())
		t.Logf("Rejected keys: %v", rejected.Keys())

		// Check that rejected key contains only kty, d, e by examining Keys()
		rejectedKeys := rejected.Keys()
		require.Contains(t, rejectedKeys, jwk.KeyTypeKey, "rejected key must have kty field")
		require.NotContains(t, rejectedKeys, "a", "rejected key should not have field 'a'")
		require.NotContains(t, rejectedKeys, "b", "rejected key should not have field 'b'")
		require.NotContains(t, rejectedKeys, "c", "rejected key should not have field 'c'")
		require.Contains(t, rejectedKeys, "d", "rejected key should have field 'd'")
		require.Contains(t, rejectedKeys, "e", "rejected key should have field 'e'")
		require.False(t, rejected.Has("a"), "rejected key should not have field 'a'")
		require.False(t, rejected.Has("b"), "rejected key should not have field 'b'")
		require.False(t, rejected.Has("c"), "rejected key should not have field 'c'")
		require.True(t, rejected.Has("d"), "rejected key should have field 'd'")
		require.True(t, rejected.Has("e"), "rejected key should have field 'e'")

		// Verify values are preserved
		val, ok := rejected.Field("d")
		require.True(t, ok, "rejected.Field should succeed")
		require.Equal(t, "value_d", val, "value for field 'd' should be preserved")
	})

	t.Run("Error handling with Clone", func(t *testing.T) {
		// Since it's hard to create a failing Clone scenario,
		// we'll just verify Filter and Reject don't panic with a simple key
		const src = `{ "kty": "oct", "k": "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ" }`

		rawKey, err := jwk.ParseKey[jwk.Key]([]byte(src))
		require.NoError(t, err, "jwk.ParseKey should succeed")

		fn := jwk.NewFieldNameFilter("a", "b", "c")
		_, err = fn.Filter(rawKey)
		require.NoError(t, err, "fn.Filter should succeed even for a basic key")

		_, err = fn.Reject(rawKey)
		require.NoError(t, err, "fn.Reject should succeed even for a basic key")
	})

	t.Run("Empty FieldNameFilter", func(t *testing.T) {
		// Create an empty FieldNameFilter
		fn := jwk.NewFieldNameFilter()

		// Create a key with fields kty, a, b, c
		const src = `{
			"kty": "oct",
			"k": "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
			"a": "value_a",
			"b": "value_b",
			"c": "value_c"
		}`

		rawKey, err := jwk.ParseKey[jwk.Key]([]byte(src))
		require.NoError(t, err, "jwk.ParseKey should succeed")

		// Filter with empty FieldNameFilter should result in a key with only kty
		filtered, err := fn.Filter(rawKey)
		require.NoError(t, err, "fn.Filter should succeed")
		keys := filtered.Keys()
		require.Len(t, keys, 1, "filtered key should have only one field (kty)")
		require.Equal(t, jwk.KeyTypeKey, keys[0], "the only field should be kty")

		// Reject with empty FieldNameFilter should result in a copy of the original key
		rejected, err := fn.Reject(rawKey)
		require.NoError(t, err, "fn.Reject should succeed")

		// Check that rejected key has the same keys as original
		originalKeys := rawKey.Keys()
		rejectedKeys := rejected.Keys()
		require.ElementsMatch(t, originalKeys, rejectedKeys, "rejected key should have the same fields as the original")
	})

	t.Run("Concurrency safety", func(t *testing.T) {
		// This is more of a logical test than an actual concurrency test
		// but it ensures the mutex is being used correctly in the Filter/Reject methods

		fn := jwk.NewFieldNameFilter("a", "b", "c")
		const src = `{
			"kty": "oct",
			"k": "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
			"a": "value_a",
			"d": "value_d"
		}`

		rawKey, err := jwk.ParseKey[jwk.Key]([]byte(src))
		require.NoError(t, err, "jwk.ParseKey should succeed")

		// Should not deadlock or have race conditions
		filtered, err := fn.Filter(rawKey)
		require.NoError(t, err, "fn.Filter should succeed")
		require.True(t, filtered.Has("a"), "filtered key should have field 'a'")
		require.False(t, filtered.Has("d"), "filtered key should not have field 'd'")

		rejected, err := fn.Reject(rawKey)
		require.NoError(t, err, "fn.Reject should succeed")
		require.False(t, rejected.Has("a"), "rejected key should not have field 'a'")
		require.True(t, rejected.Has("d"), "rejected key should have field 'd'")
	})
}

func TestStandardFieldsFilter(t *testing.T) {
	t.Run("Filter standard fields", func(t *testing.T) {
		// Create a key with standard and custom fields
		const src = `{
			"kty": "EC",
			"crv": "P-256",
			"x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
			"y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
			"kid": "kid-value",
			"use": "sig",
			"key_ops": ["sign", "verify"],
			"alg": "ES256",
			"x5u": "https://example.com/x509",
			"x5c": ["cert1", "cert2"],
			"x5t": "thumbprint",
			"x5t#S256": "thumbprint-s256",
			"custom1": "value1",
			"custom2": "value2"
		}`

		rawKey, err := jwk.ParseKey[jwk.Key]([]byte(src))
		require.NoError(t, err, "jwk.ParseKey should succeed")
		require.NotNil(t, rawKey, "key should not be nil")

		stdFilter := jwk.ECDSAStandardFieldsFilter()

		t.Run("Filter standard fields", func(t *testing.T) {
			// Filter should return a key with only standard fields
			filtered, err := stdFilter.Filter(rawKey)
			require.NoError(t, err, "filter.Filter should succeed")

			// Debug: print keys for inspection
			t.Logf("Original keys: %v", rawKey.Keys())
			t.Logf("Filtered keys: %v", filtered.Keys())

			// Verify standard fields are present by examining Keys()
			filteredKeys := filtered.Keys()
			require.Contains(t, filteredKeys, jwk.KeyTypeKey, "filtered key should have kty field")
			require.Contains(t, filteredKeys, jwk.KeyIDKey, "filtered key should have kid field")
			require.Contains(t, filteredKeys, jwk.KeyUsageKey, "filtered key should have use field")
			require.Contains(t, filteredKeys, jwk.KeyOpsKey, "filtered key should have key_ops field")
			require.Contains(t, filteredKeys, jwk.AlgorithmKey, "filtered key should have alg field")
			require.Contains(t, filteredKeys, jwk.X509URLKey, "filtered key should have x5u field")
			require.Contains(t, filteredKeys, jwk.X509CertChainKey, "filtered key should have x5c field")
			require.Contains(t, filteredKeys, jwk.X509CertThumbprintKey, "filtered key should have x5t field")
			require.Contains(t, filteredKeys, jwk.X509CertThumbprintS256Key, "filtered key should have x5t#S256 field")

			// Verify custom fields are not present
			require.NotContains(t, filteredKeys, "custom1", "filtered key should not have custom1 field")
			require.NotContains(t, filteredKeys, "custom2", "filtered key should not have custom2 field")

			// Verify values are preserved
			kid, ok := filtered.Field(jwk.KeyIDKey)
			require.True(t, ok, "filtered.Field should succeed")
			require.Equal(t, "kid-value", kid, "value for kid field should be preserved")
		})

		t.Run("Reject standard fields", func(t *testing.T) {
			// Reject should return a key with only custom fields
			rejected, err := stdFilter.Reject(rawKey)
			require.NoError(t, err, "filter.Reject should succeed")

			// Debug: print keys for inspection
			t.Logf("Original keys: %v", rawKey.Keys())
			t.Logf("Rejected keys: %v", rejected.Keys())

			// Verify standard fields are not present (except kty which cannot be removed)
			rejectedKeys := rejected.Keys()
			require.Contains(t, rejectedKeys, jwk.KeyTypeKey, "rejected key must have kty field")
			require.NotContains(t, rejectedKeys, jwk.KeyIDKey, "rejected key should not have kid field")
			require.NotContains(t, rejectedKeys, jwk.KeyUsageKey, "rejected key should not have use field")
			require.NotContains(t, rejectedKeys, jwk.KeyOpsKey, "rejected key should not have key_ops field")
			require.NotContains(t, rejectedKeys, jwk.AlgorithmKey, "rejected key should not have alg field")
			require.NotContains(t, rejectedKeys, jwk.X509URLKey, "rejected key should not have x5u field")
			require.NotContains(t, rejectedKeys, jwk.X509CertChainKey, "rejected key should not have x5c field")
			require.NotContains(t, rejectedKeys, jwk.X509CertThumbprintKey, "rejected key should not have x5t field")
			require.NotContains(t, rejectedKeys, jwk.X509CertThumbprintS256Key, "rejected key should not have x5t#S256 field")

			// Verify custom fields are present
			require.True(t, rejected.Has("custom1"), "rejected key should have custom1 field")
			require.True(t, rejected.Has("custom2"), "rejected key should have custom2 field")

			// Verify values are preserved
			customValue, ok := rejected.Field("custom1")
			require.True(t, ok, "rejected.Field should succeed")
			require.Equal(t, "value1", customValue, "value for custom1 field should be preserved")
		})
	})
}
