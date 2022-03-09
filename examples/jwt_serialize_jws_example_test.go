package examples_test

import (
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func ExampleJWT_SerializeJWS() {
	tok, err := jwt.NewBuilder().
		Issuer(`github.com/lestrrat-go/jwx`).
		IssuedAt(time.Unix(aLongLongTimeAgo, 0)).
		Build()
	if err != nil {
		fmt.Printf("failed to build token: %s\n", err)
		return
	}

	key, err := jwk.FromRaw([]byte(`abracadavra`))
	if err != nil {
		fmt.Printf("failed to create symmetric key: %s\n", err)
		return
	}

	serialized, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256, key))
	if err != nil {
		fmt.Printf("failed to sign token: %s\n", err)
		return
	}

	fmt.Printf("%s\n", serialized)
	// OUTPUT:
	// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjIzMzQzMTIwMCwiaXNzIjoiZ2l0aHViLmNvbS9sZXN0cnJhdC1nby9qd3gifQ.rTlpyVnHFWosNud7seqlsvhM8UoXUIAKfdWHySFO5Ro
}
