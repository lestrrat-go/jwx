package examples_test

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

func ExampleJWT_FlattenAudience() {
	// Sometimes you need to "flatten" the "aud" claim because of
	// parsers developed by people who apparently didn't read the RFC.
	//
	// In such cases, you can control the behavior of the JSON
	// emitted when tokens are converted to JSON by tweaking the
	// per-token options set.

	{ // Case 1: the per-object way
		tok, err := jwt.NewBuilder().
			Audience([]string{`foo`}).
			Build()
		if err != nil {
			fmt.Printf("failed to build token: %s\n", err)
			return
		}

		// Only this particular instance of the token is affected
		tok.Options().Enable(jwt.FlattenAudience)
		json.NewEncoder(os.Stdout).Encode(tok)
	}

	{ // Case 2: globally enabling flattened audience
		// NOTE: This example DOES NOT flatten the audience
		// because the call to change this global settings has been
		// commented out. Setting this has GLOBAL effects, and would
		// alter the output of other examples.
		//
		// If you would like to try this, UNCOMMENT the line below
		//
		// // UNCOMMENT THIS LINE BELOW
		// jwt.Settings(jwt.WithFlattenAudience(true))
		//
		// ...and if you are running from the examples directory, run
		// this example in isolation by invoking
		//
		//   go test -run=ExampleJWT_FlattenAudience
		//
		// You may see the example fail, but that's because the OUTPUT line
		// expects the global settings to be DISABLED. In order to make
		// the example pass, change the second line from OUTPUT below
		//
		//   from: {"aud":["foo"]}
		//   to  : {"aud":"foo"}
		//
		// Please note that it is recommended you ONLY set the jwt.Settings(jwt.WithFlattenedAudience(true))
		// once at the beginning of your main program (probably in an `init()` function)
		// so that you do not need to worry about causing issues depending
		// on when tokens are created relative to the time when
		// the global setting is changed.

		tok, err := jwt.NewBuilder().
			Audience([]string{`foo`}).
			Build()
		if err != nil {
			fmt.Printf("failed to build token: %s\n", err)
			return
		}

		// This would flatten the "aud" claim if the appropriate
		// line above has been uncommented
		json.NewEncoder(os.Stdout).Encode(tok)

		// This would force this particular object not to flatten the
		// "aud" claim. All other tokens would be constructed with the
		// option enabled
		tok.Options().Enable(jwt.FlattenAudience)
		json.NewEncoder(os.Stdout).Encode(tok)
	}
	// OUTPUT:
	// {"aud":"foo"}
	// {"aud":["foo"]}
	// {"aud":"foo"}
}
