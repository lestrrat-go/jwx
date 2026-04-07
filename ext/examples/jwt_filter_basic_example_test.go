package examples_test

import (
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwt"
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
	if _, err := customFilter.Filter(token); err != nil {
		fmt.Printf("failed to filter custom claims: %s\n", err)
		return
	}
	// You could also use Reject to get all claims except the specified ones
	// Note that this may include other non-standard claims
	if _, err := customFilter.Reject(token); err != nil {
		fmt.Printf("failed to reject custom claims: %s\n", err)
		return
	}

	// Use StandardClaimsFilter to get only standard JWT claims
	if _, err = jwt.StandardClaimsFilter().Filter(token); err != nil {
		fmt.Printf("failed to filter standard claims: %s\n", err)
		return
	}

	// Use StandardClaimsFilter to reject standard claims, resulting
	// in every non-standard claim being retained
	if _, err = jwt.StandardClaimsFilter().Reject(token); err != nil {
		fmt.Printf("failed to reject standard claims: %s\n", err)
		return
	}

	// OUTPUT:
}
