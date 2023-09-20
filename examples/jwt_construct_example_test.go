package examples_test

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

func ExampleJWT_Construct() {
	tok := jwt.New()
	if err := tok.Set(jwt.IssuerKey, `github.com/lestrrat-go/jwx`); err != nil {
		fmt.Printf("failed to set claim: %s\n", err)
		return
	}
	if err := tok.Set(jwt.AudienceKey, `users`); err != nil {
		fmt.Printf("failed to set claim: %s\n", err)
		return
	}

	if err := json.NewEncoder(os.Stdout).Encode(tok); err != nil {
		fmt.Printf("failed to encode to JSON: %s\n", err)
		return
	}
	// OUTPUT:
	// {"aud":["users"],"iss":"github.com/lestrrat-go/jwx"}
}
