package examples_test

import (
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

func Example_jwt_filter_basic_claims() {
	// Create a token with standard and custom claims
	token, err := jwt.NewBuilder().
		Issuer("github.com/lestrrat-go/jwx").
		Subject("jwt_filter_example").
		Audience([]string{"developers", "users"}).
		IssuedAt(time.Unix(1234567890, 0)).
		Expiration(time.Unix(1234567890+3600, 0)).
		Claim("customClaim", "customValue").
		Claim("applicationRole", "admin").
		Claim("department", "engineering").
		Build()
	if err != nil {
		fmt.Printf("failed to build token: %s\n", err)
		return
	}

	// Create a custom claim name filter
	customFilter := jwt.NewClaimNameFilter("customClaim", "applicationRole", "department")

	// Filter to get only custom claims
	_, err = customFilter.Filter(token)
	if err != nil {
		fmt.Printf("failed to filter custom claims: %s\n", err)
		return
	}

	// Use StandardClaimsFilter to get only standard JWT claims
	standardFilter := jwt.StandardClaimsFilter()
	_, err = standardFilter.Filter(token)
	if err != nil {
		fmt.Printf("failed to filter standard claims: %s\n", err)
		return
	}

	// OUTPUT:
}
