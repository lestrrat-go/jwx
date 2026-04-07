package examples_test

import (
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwt"
)

func Example_jwt_filter_advanced_use_cases() {
	// Create a comprehensive token with various types of claims
	token, err := jwt.NewBuilder().
		Issuer("auth-service.example.com").
		Subject("user-456").
		Audience([]string{"web-app", "mobile-app", "api-gateway"}).
		IssuedAt(time.Unix(1234567890, 0)).
		Expiration(time.Unix(1234567890+7200, 0)).
		NotBefore(time.Unix(1234567890, 0)).
		JwtID("session-xyz789").
		Claim("userRole", "manager").
		Claim("department", "sales").
		Claim("permissions", []string{"read:reports", "write:orders", "approve:discounts"}).
		Claim("profile", map[string]any{
			"name":  "John Doe",
			"email": "john@example.com",
			"phone": "+1-555-0123",
		}).
		Claim("sessionInfo", map[string]any{
			"loginIP":      "10.0.1.100",
			"deviceType":   "desktop",
			"browser":      "Chrome/91.0",
			"lastActivity": "2023-01-01T12:30:00Z",
		}).
		Claim("features", []string{"beta-ui", "advanced-analytics", "mobile-push"}).
		Build()
	if err != nil {
		fmt.Printf("failed to build comprehensive token: %s\n", err)
		return
	}

	// Use case 1: Create a token for public APIs (remove sensitive information)
	sensitiveFilter := jwt.NewClaimNameFilter("sessionInfo", "profile")
	if _, err := sensitiveFilter.Reject(token); err != nil {
		fmt.Printf("failed to create public API token: %s\n", err)
		return
	}

	// Use case 2: Create an identity-only token (only user identification claims)
	identityFilter := jwt.NewClaimNameFilter("sub", "iss", "userRole", "department")
	if _, err := identityFilter.Filter(token); err != nil {
		fmt.Printf("failed to create identity token: %s\n", err)
		return
	}

	// Use case 3: Create a minimal security token (only time-based and security claims)
	securityFilter := jwt.NewClaimNameFilter("iss", "sub", "aud", "exp", "iat", "nbf", "jti")
	if _, err := securityFilter.Filter(token); err != nil {
		fmt.Printf("failed to create security token: %s\n", err)
		return
	}

	// Use case 4: Combine filters - remove both standard claims and specific custom claims
	standardFilter := jwt.StandardClaimsFilter()
	tempToken, err := standardFilter.Reject(token) // Remove standard claims first
	if err != nil {
		fmt.Printf("failed to remove standard claims: %s\n", err)
		return
	}

	// Then remove specific custom claims
	customSensitiveFilter := jwt.NewClaimNameFilter("sessionInfo", "profile")
	if _, err := customSensitiveFilter.Reject(tempToken); err != nil {
		fmt.Printf("failed to remove custom sensitive claims: %s\n", err)
		return
	}

	// OUTPUT:
}
