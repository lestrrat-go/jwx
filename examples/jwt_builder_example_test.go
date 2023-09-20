package examples_test

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

func ExampleJWT_Builder() {
	tok, err := jwt.NewBuilder().
		Claim(`claim1`, `value1`).
		Claim(`claim2`, `value2`).
		Issuer(`github.com/lestrrat-go/jwx`).
		Audience([]string{`users`}).
		Build()
	if err != nil {
		fmt.Printf("failed to build token: %s\n", err)
		return
	}
	if err := json.NewEncoder(os.Stdout).Encode(tok); err != nil {
		fmt.Printf("failed to encode to JSON: %s\n", err)
		return
	}
	// OUTPUT:
	// {"aud":["users"],"claim1":"value1","claim2":"value2","iss":"github.com/lestrrat-go/jwx"}
}
