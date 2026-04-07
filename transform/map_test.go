package transform_test

import (
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/lestrrat-go/jwx/v4/transform"
	"github.com/stretchr/testify/require"
)

func TestAsMapWithJWTToken(t *testing.T) {
	t.Run("Basic JWT Token with standard claims", func(t *testing.T) {
		// Create a JWT token with standard claims
		token := jwt.New()
		expectedTime := time.Unix(1234567890, 0).UTC()

		require.NoError(t, token.Set(jwt.IssuerKey, "https://example.com"))
		require.NoError(t, token.Set(jwt.SubjectKey, "user123"))
		require.NoError(t, token.Set(jwt.AudienceKey, []string{"api", "web"}))
		require.NoError(t, token.Set(jwt.IssuedAtKey, expectedTime))
		require.NoError(t, token.Set(jwt.ExpirationKey, expectedTime.Add(time.Hour)))
		require.NoError(t, token.Set(jwt.NotBeforeKey, expectedTime))
		require.NoError(t, token.Set(jwt.JwtIDKey, "jwt-id-123"))

		dst := make(map[string]any)
		err := transform.AsMap(token, dst)
		require.NoError(t, err, "AsMap should succeed")

		// Verify all standard claims are present
		require.Equal(t, "https://example.com", dst[jwt.IssuerKey])
		require.Equal(t, "user123", dst[jwt.SubjectKey])
		require.Equal(t, []string{"api", "web"}, dst[jwt.AudienceKey])
		require.Equal(t, expectedTime, dst[jwt.IssuedAtKey])
		require.Equal(t, expectedTime.Add(time.Hour), dst[jwt.ExpirationKey])
		require.Equal(t, expectedTime, dst[jwt.NotBeforeKey])
		require.Equal(t, "jwt-id-123", dst[jwt.JwtIDKey])
	})

	t.Run("JWT Token with private claims", func(t *testing.T) {
		token := jwt.New()

		// Set standard claims
		require.NoError(t, token.Set(jwt.IssuerKey, "test-issuer"))
		require.NoError(t, token.Set(jwt.SubjectKey, "test-subject"))

		// Set private claims
		require.NoError(t, token.Set("custom_claim", "custom_value"))
		require.NoError(t, token.Set("user_role", "admin"))
		require.NoError(t, token.Set("permissions", []string{"read", "write", "delete"}))
		require.NoError(t, token.Set("metadata", map[string]any{
			"version": "1.0",
			"source":  "test",
		}))

		dst := make(map[string]any)
		err := transform.AsMap(token, dst)
		require.NoError(t, err, "AsMap should succeed")

		// Verify standard claims
		require.Equal(t, "test-issuer", dst[jwt.IssuerKey])
		require.Equal(t, "test-subject", dst[jwt.SubjectKey])

		// Verify private claims
		require.Equal(t, "custom_value", dst["custom_claim"])
		require.Equal(t, "admin", dst["user_role"])
		require.Equal(t, []string{"read", "write", "delete"}, dst["permissions"])

		metadata, ok := dst["metadata"].(map[string]any)
		require.True(t, ok, "metadata should be a map")
		require.Equal(t, "1.0", metadata["version"])
		require.Equal(t, "test", metadata["source"])
	})

	t.Run("Empty JWT Token", func(t *testing.T) {
		token := jwt.New()

		dst := make(map[string]any)
		err := transform.AsMap(token, dst)
		require.NoError(t, err, "AsMap should succeed for empty token")

		// Should have no keys since no claims were set
		require.Len(t, dst, 0, "Empty token should result in empty map")
	})

	t.Run("JWT Token with single claim", func(t *testing.T) {
		token := jwt.New()
		require.NoError(t, token.Set(jwt.IssuerKey, "single-issuer"))

		dst := make(map[string]any)
		err := transform.AsMap(token, dst)
		require.NoError(t, err, "AsMap should succeed")

		require.Len(t, dst, 1, "Should have exactly one key")
		require.Equal(t, "single-issuer", dst[jwt.IssuerKey])
	})

	t.Run("JWT Token with various data types", func(t *testing.T) {
		token := jwt.New()

		// Test different data types
		require.NoError(t, token.Set("string_claim", "string value"))
		require.NoError(t, token.Set("int_claim", 42))
		require.NoError(t, token.Set("bool_claim", true))
		require.NoError(t, token.Set("float_claim", 3.14))
		require.NoError(t, token.Set("array_claim", []any{"a", "b", "c"}))
		require.NoError(t, token.Set("null_claim", nil))

		dst := make(map[string]any)
		err := transform.AsMap(token, dst)
		require.NoError(t, err, "AsMap should succeed")

		require.Equal(t, "string value", dst["string_claim"])
		require.Equal(t, 42, dst["int_claim"])
		require.Equal(t, true, dst["bool_claim"])
		require.Equal(t, 3.14, dst["float_claim"])
		require.Equal(t, []any{"a", "b", "c"}, dst["array_claim"])
		require.Nil(t, dst["null_claim"])
	})

	t.Run("Nil destination map should return error", func(t *testing.T) {
		token := jwt.New()
		require.NoError(t, token.Set(jwt.IssuerKey, "test"))

		err := transform.AsMap(token, nil)
		require.Error(t, err, "AsMap should fail with nil destination")
		require.Contains(t, err.Error(), "destination map cannot be nil")
	})

	t.Run("Pre-populated destination map should be extended", func(t *testing.T) {
		token := jwt.New()
		require.NoError(t, token.Set(jwt.IssuerKey, "token-issuer"))
		require.NoError(t, token.Set("custom_claim", "token-value"))

		// Pre-populate destination map
		dst := map[string]any{
			"existing_key": "existing_value",
			"another_key":  123,
		}

		err := transform.AsMap(token, dst)
		require.NoError(t, err, "AsMap should succeed")

		// Original keys should still be present
		require.Equal(t, "existing_value", dst["existing_key"])
		require.Equal(t, 123, dst["another_key"])

		// New keys from token should be added
		require.Equal(t, "token-issuer", dst[jwt.IssuerKey])
		require.Equal(t, "token-value", dst["custom_claim"])

		require.Len(t, dst, 4, "Should have 4 total keys")
	})

	t.Run("Overlapping keys should be overwritten", func(t *testing.T) {
		token := jwt.New()
		require.NoError(t, token.Set(jwt.IssuerKey, "token-issuer"))
		require.NoError(t, token.Set("shared_key", "token-value"))

		// Pre-populate with overlapping keys
		dst := map[string]any{
			jwt.IssuerKey: "original-issuer",
			"shared_key":  "original-value",
			"unique_key":  "unique-value",
		}

		err := transform.AsMap(token, dst)
		require.NoError(t, err, "AsMap should succeed")

		// Overlapping keys should be overwritten with token values
		require.Equal(t, "token-issuer", dst[jwt.IssuerKey])
		require.Equal(t, "token-value", dst["shared_key"])

		// Unique key should remain unchanged
		require.Equal(t, "unique-value", dst["unique_key"])

		require.Len(t, dst, 3, "Should have 3 total keys")
	})
}
