package examples_test

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
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
		Claim("profile", map[string]interface{}{
			"name":  "John Doe",
			"email": "john@example.com",
			"phone": "+1-555-0123",
		}).
		Claim("sessionInfo", map[string]interface{}{
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
	publicAPIToken, err := sensitiveFilter.Reject(token)
	if err != nil {
		fmt.Printf("failed to create public API token: %s\n", err)
		return
	}

	fmt.Println("Public API token (sensitive data removed):")
	buf, err := json.MarshalIndent(publicAPIToken, "", "  ")
	if err != nil {
		fmt.Printf("failed to marshal public API token: %s\n", err)
		return
	}
	fmt.Printf("%s\n", buf)

	// Use case 2: Create an identity-only token (only user identification claims)
	identityFilter := jwt.NewClaimNameFilter("sub", "iss", "userRole", "department")
	identityToken, err := identityFilter.Filter(token)
	if err != nil {
		fmt.Printf("failed to create identity token: %s\n", err)
		return
	}

	fmt.Println("Identity token (user identification only):")
	buf, err = json.MarshalIndent(identityToken, "", "  ")
	if err != nil {
		fmt.Printf("failed to marshal identity token: %s\n", err)
		return
	}
	fmt.Printf("%s\n", buf)

	// Use case 3: Create a minimal security token (only time-based and security claims)
	securityFilter := jwt.NewClaimNameFilter("iss", "sub", "aud", "exp", "iat", "nbf", "jti")
	securityToken, err := securityFilter.Filter(token)
	if err != nil {
		fmt.Printf("failed to create security token: %s\n", err)
		return
	}

	fmt.Println("Security token (time-based and security claims only):")
	buf, err = json.MarshalIndent(securityToken, "", "  ")
	if err != nil {
		fmt.Printf("failed to marshal security token: %s\n", err)
		return
	}
	fmt.Printf("%s\n", buf)

	// Use case 4: Combine filters - remove both standard claims and specific custom claims
	standardFilter := jwt.StandardClaimsFilter()
	tempToken, err := standardFilter.Reject(token) // Remove standard claims first
	if err != nil {
		fmt.Printf("failed to remove standard claims: %s\n", err)
		return
	}

	// Then remove specific custom claims
	customSensitiveFilter := jwt.NewClaimNameFilter("sessionInfo", "profile")
	finalToken, err := customSensitiveFilter.Reject(tempToken)
	if err != nil {
		fmt.Printf("failed to remove custom sensitive claims: %s\n", err)
		return
	}

	fmt.Println("Combined filtering result (non-standard, non-sensitive claims only):")
	buf, err = json.MarshalIndent(finalToken, "", "  ")
	if err != nil {
		fmt.Printf("failed to marshal final token: %s\n", err)
		return
	}
	fmt.Printf("%s\n", buf)

	// OUTPUT:
	// Public API token (sensitive data removed):
	// {
	//   "aud": [
	//     "web-app",
	//     "mobile-app",
	//     "api-gateway"
	//   ],
	//   "department": "sales",
	//   "exp": 1234575090,
	//   "features": [
	//     "beta-ui",
	//     "advanced-analytics",
	//     "mobile-push"
	//   ],
	//   "iat": 1234567890,
	//   "iss": "auth-service.example.com",
	//   "jti": "session-xyz789",
	//   "nbf": 1234567890,
	//   "permissions": [
	//     "read:reports",
	//     "write:orders",
	//     "approve:discounts"
	//   ],
	//   "sub": "user-456",
	//   "userRole": "manager"
	// }
	// Identity token (user identification only):
	// {
	//   "department": "sales",
	//   "iss": "auth-service.example.com",
	//   "sub": "user-456",
	//   "userRole": "manager"
	// }
	// Security token (time-based and security claims only):
	// {
	//   "aud": [
	//     "web-app",
	//     "mobile-app",
	//     "api-gateway"
	//   ],
	//   "exp": 1234575090,
	//   "iat": 1234567890,
	//   "iss": "auth-service.example.com",
	//   "jti": "session-xyz789",
	//   "nbf": 1234567890,
	//   "sub": "user-456"
	// }
	// Combined filtering result (non-standard, non-sensitive claims only):
	// {
	//   "department": "sales",
	//   "features": [
	//     "beta-ui",
	//     "advanced-analytics",
	//     "mobile-push"
	//   ],
	//   "permissions": [
	//     "read:reports",
	//     "write:orders",
	//     "approve:discounts"
	//   ],
	//   "userRole": "manager"
	// }
}
