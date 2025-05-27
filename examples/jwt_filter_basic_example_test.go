package examples_test

import (
	"encoding/json"
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
	customOnlyToken, err := customFilter.Filter(token)
	if err != nil {
		fmt.Printf("failed to filter custom claims: %s\n", err)
		return
	}

	fmt.Println("Custom claims only:")
	buf, err := json.MarshalIndent(customOnlyToken, "", "  ")
	if err != nil {
		fmt.Printf("failed to marshal custom token: %s\n", err)
		return
	}
	fmt.Printf("%s\n", buf)

	// Use StandardClaimsFilter to get only standard JWT claims
	standardFilter := jwt.StandardClaimsFilter()
	standardOnlyToken, err := standardFilter.Filter(token)
	if err != nil {
		fmt.Printf("failed to filter standard claims: %s\n", err)
		return
	}

	fmt.Println("Standard claims only:")
	buf, err = json.MarshalIndent(standardOnlyToken, "", "  ")
	if err != nil {
		fmt.Printf("failed to marshal standard token: %s\n", err)
		return
	}
	fmt.Printf("%s\n", buf)

	// OUTPUT:
	// Custom claims only:
	// {
	//   "applicationRole": "admin",
	//   "customClaim": "customValue",
	//   "department": "engineering"
	// }
	// Standard claims only:
	// {
	//   "aud": [
	//     "developers",
	//     "users"
	//   ],
	//   "exp": 1234571490,
	//   "iat": 1234567890,
	//   "iss": "github.com/lestrrat-go/jwx",
	//   "sub": "jwt_filter_example"
	// }
}
