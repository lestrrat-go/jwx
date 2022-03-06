package examples_test

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

func ExampleJWT_FlattenAudience() {
	// This bit has been commented out because it would have
	// global effect in all of the examples. Create a init()
	// function with the following code if you are using it
	// in producion
	//
	// jwt.Settings(jwt.WithFlattenAudience(true))

	tok, err := jwt.NewBuilder().
		Audience([]string{`foo`}).
		Build()
	if err != nil {
		fmt.Printf("failed to build token: %s\n", err)
		return
	}

	json.NewEncoder(os.Stdout).Encode(tok)

	// If the flattened audience is enabled, the following shoud
	// result in an error, and produce `{"aud":"foo"}`

	// OUTPUT:
	// {"aud":["foo"]}
}
