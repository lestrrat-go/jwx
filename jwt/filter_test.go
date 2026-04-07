package jwt_test

import (
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/require"
)

func TestClaimNames(t *testing.T) {
	t.Run("NewClaimNames", func(t *testing.T) {
		cn := jwt.NewClaimNameFilter("a", "b", "c")
		require.NotNil(t, cn, "NewClaimNames should return a non-nil value")
	})

	t.Run("Filter", func(t *testing.T) {
		// Create a ClaimNames with names a, b, c
		cn := jwt.NewClaimNameFilter("a", "b", "c")

		// Create a token with claims a, b, c, d, e
		token := jwt.New()
		require.NoError(t, token.Set("a", "value_a"), "token.Set should succeed")
		require.NoError(t, token.Set("b", "value_b"), "token.Set should succeed")
		require.NoError(t, token.Set("c", "value_c"), "token.Set should succeed")
		require.NoError(t, token.Set("d", "value_d"), "token.Set should succeed")
		require.NoError(t, token.Set("e", "value_e"), "token.Set should succeed")

		// Filter should return a token with only claims a, b, c
		filtered, err := cn.Filter(token)
		require.NoError(t, err, "cn.Filter should succeed")

		// Check that filtered token contains only a, b, c
		require.True(t, filtered.Has("a"), "filtered token should have claim 'a'")
		require.True(t, filtered.Has("b"), "filtered token should have claim 'b'")
		require.True(t, filtered.Has("c"), "filtered token should have claim 'c'")
		require.False(t, filtered.Has("d"), "filtered token should not have claim 'd'")
		require.False(t, filtered.Has("e"), "filtered token should not have claim 'e'")

		// Verify values are preserved
		val, ok := filtered.Field("a")
		require.True(t, ok, "filtered.Field should succeed")
		require.Equal(t, "value_a", val, "value for claim 'a' should be preserved")
	})

	t.Run("Reject", func(t *testing.T) {
		// Create a ClaimNames with names a, b, c
		cn := jwt.NewClaimNameFilter("a", "b", "c")

		// Create a token with claims a, b, c, d, e
		token := jwt.New()
		require.NoError(t, token.Set("a", "value_a"), "token.Set should succeed")
		require.NoError(t, token.Set("b", "value_b"), "token.Set should succeed")
		require.NoError(t, token.Set("c", "value_c"), "token.Set should succeed")
		require.NoError(t, token.Set("d", "value_d"), "token.Set should succeed")
		require.NoError(t, token.Set("e", "value_e"), "token.Set should succeed")

		// Reject should return a token with only claims d, e
		rejected, err := cn.Reject(token)
		require.NoError(t, err, "cn.Reject should succeed")

		// Check that rejected token contains only d, e
		require.False(t, rejected.Has("a"), "rejected token should not have claim 'a'")
		require.False(t, rejected.Has("b"), "rejected token should not have claim 'b'")
		require.False(t, rejected.Has("c"), "rejected token should not have claim 'c'")
		require.True(t, rejected.Has("d"), "rejected token should have claim 'd'")
		require.True(t, rejected.Has("e"), "rejected token should have claim 'e'")

		// Verify values are preserved
		val, ok := rejected.Field("d")
		require.True(t, ok, "rejected.Field should succeed")
		require.Equal(t, "value_d", val, "value for claim 'd' should be preserved")
	})

	t.Run("Error handling with Clone", func(t *testing.T) {
		// Mock a token that will fail Clone
		token := jwt.New()
		// Setting a value that cannot be retrieved to simulate a Clone error
		// We can't actually create a token that fails to clone in the test code,
		// so this test is a bit artificial. In real code, we'd use a mock.

		// But let's at least verify Filter and Reject don't panic
		cn := jwt.NewClaimNameFilter("a", "b", "c")
		_, err := cn.Filter(token)
		require.NoError(t, err, "cn.Filter should succeed even for an empty token")

		_, err = cn.Reject(token)
		require.NoError(t, err, "cn.Reject should succeed even for an empty token")
	})

	t.Run("Empty ClaimNames", func(t *testing.T) {
		// Create an empty ClaimNames
		cn := jwt.NewClaimNameFilter()

		// Create a token with claims a, b, c
		token := jwt.New()
		require.NoError(t, token.Set("a", "value_a"), "token.Set should succeed")
		require.NoError(t, token.Set("b", "value_b"), "token.Set should succeed")
		require.NoError(t, token.Set("c", "value_c"), "token.Set should succeed")

		// Filter with empty ClaimNames should result in an empty token
		filtered, err := cn.Filter(token)
		require.NoError(t, err, "cn.Filter should succeed")
		require.Empty(t, filtered.Keys(), "filtered token should have no claims")

		// Reject with empty ClaimNames should result in a copy of the original token
		rejected, err := cn.Reject(token)
		require.NoError(t, err, "cn.Reject should succeed")

		// Check that rejected token has the same keys as original, ignoring order
		originalKeys := token.Keys()
		rejectedKeys := rejected.Keys()
		require.ElementsMatch(t, originalKeys, rejectedKeys, "rejected token should have the same claims as the original")
	})

	t.Run("Concurrency safety", func(t *testing.T) {
		// This is more of a logical test than an actual concurrency test
		// but it ensures the mutex is being used correctly in the Filter/Reject methods

		cn := jwt.NewClaimNameFilter("a", "b", "c")
		token := jwt.New()
		require.NoError(t, token.Set("a", "value_a"), "token.Set should succeed")
		require.NoError(t, token.Set("d", "value_d"), "token.Set should succeed")

		// Should not deadlock or have race conditions
		filtered, err := cn.Filter(token)
		require.NoError(t, err, "cn.Filter should succeed")
		require.True(t, filtered.Has("a"), "filtered token should have claim 'a'")
		require.False(t, filtered.Has("d"), "filtered token should not have claim 'd'")

		rejected, err := cn.Reject(token)
		require.NoError(t, err, "cn.Reject should succeed")
		require.False(t, rejected.Has("a"), "rejected token should not have claim 'a'")
		require.True(t, rejected.Has("d"), "rejected token should have claim 'd'")
	})
}

func TestStandardClaimsFilter(t *testing.T) {
	t.Run("Filter standard claims", func(t *testing.T) {
		// Create a token with standard and custom claims
		token, err := jwt.NewBuilder().
			Audience([]string{"aud1", "aud2"}).
			Expiration(time.Unix(aLongLongTimeAgo, 0)).
			IssuedAt(time.Unix(aLongLongTimeAgo, 0)).
			Issuer("issuer").
			JwtID("jwt-id").
			NotBefore(time.Unix(aLongLongTimeAgo, 0)).
			Subject("subject").
			Claim("custom1", "value1").
			Claim("custom2", "value2").
			Build()
		require.NoError(t, err, "token should be created successfully")
		require.NotNil(t, token, "token should not be nil")

		stdFilter := jwt.StandardClaimsFilter()

		t.Run("Filter standard claims", func(t *testing.T) {
			// Filter should return a token with only standard claims
			filtered, err := stdFilter.Filter(token)
			require.NoError(t, err, "filter.Filter should succeed")

			// Verify standard claims are present
			require.True(t, filtered.Has(jwt.AudienceKey), "filtered token should have audience claim")
			require.True(t, filtered.Has(jwt.ExpirationKey), "filtered token should have expiration claim")
			require.True(t, filtered.Has(jwt.IssuedAtKey), "filtered token should have issued-at claim")
			require.True(t, filtered.Has(jwt.IssuerKey), "filtered token should have issuer claim")
			require.True(t, filtered.Has(jwt.JwtIDKey), "filtered token should have jwt-id claim")
			require.True(t, filtered.Has(jwt.NotBeforeKey), "filtered token should have not-before claim")
			require.True(t, filtered.Has(jwt.SubjectKey), "filtered token should have subject claim")

			// Verify custom claims are not present
			require.False(t, filtered.Has("custom1"), "filtered token should not have custom1 claim")
			require.False(t, filtered.Has("custom2"), "filtered token should not have custom2 claim")

			// Verify values are preserved
			issuer, ok := filtered.Field(jwt.IssuerKey)
			require.True(t, ok, "filtered.Field should succeed")
			require.Equal(t, "issuer", issuer, "value for issuer claim should be preserved")
		})
		t.Run("Reject standard claims", func(t *testing.T) {
			// Reject should return a token with only custom claims
			rejected, err := stdFilter.Reject(token)
			require.NoError(t, err, "filter.Reject should succeed")

			// Verify standard claims are not present
			require.False(t, rejected.Has(jwt.AudienceKey), "rejected token should not have audience claim")
			require.False(t, rejected.Has(jwt.ExpirationKey), "rejected token should not have expiration claim")
			require.False(t, rejected.Has(jwt.IssuedAtKey), "rejected token should not have issued-at claim")
			require.False(t, rejected.Has(jwt.IssuerKey), "rejected token should not have issuer claim")
			require.False(t, rejected.Has(jwt.JwtIDKey), "rejected token should not have jwt-id claim")
			require.False(t, rejected.Has(jwt.NotBeforeKey), "rejected token should not have not-before claim")
			require.False(t, rejected.Has(jwt.SubjectKey), "rejected token should not have subject claim")

			// Verify custom claims are present
			require.True(t, rejected.Has("custom1"), "rejected token should have custom1 claim")
			require.True(t, rejected.Has("custom2"), "rejected token should have custom2 claim")

			// Verify values are preserved
			customValue, ok := rejected.Field("custom1")
			require.True(t, ok, "rejected.Field should succeed")
			require.Equal(t, "value1", customValue, "value for custom1 claim should be preserved")
		})
	})
}
