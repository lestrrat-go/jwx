package examples_test

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

func ExampleJWT_GetClaims() {
	tok, err := jwt.NewBuilder().
		IssuedAt(time.Now()).
		Issuer(`github.com/lestrrat-go/jwx`).
		Subject(`example`).
		Claim(`claim1`, `value1`).
		Claim(`claim2`, `2022-05-16T07:35:56+00:00`).
		Build()
	if err != nil {
		fmt.Printf("failed to build token: %s\n", err)
		return
	}

	// Pre-defined fields have typed accessors.
	var _ time.Time = tok.IssuedAt()
	var _ string = tok.Issuer()
	var _ string = tok.Subject()

	var v interface{}
	var ok bool

	// But you can also get them via the generic `.Get()` method.
	// However, v is of type interface{}, so you might need to
	// use a type switch to properly use its value.
	//
	// For the key name you could also use jwt.IssuedAtKey constant
	{ // case 1: untyped. use this when you don't know the type of the value
		var v interface{}
		if err := tok.Get(`iat`, &v); err != nil {
			fmt.Printf(`failed to retrieve iat: %s`, err)
			return
		}
	}
	{ // case 2: you know the type of the field before hand
		var v time.Time
		if err := tok.Get(`iat`, &v); err != nil {
			fmt.Printf(`failed to retrieve iat: %s`, err)
			return
		}
	}

	// Same thing for private claims
	var claim1, claim2 interface{}
	if err := tok.Get(`claim1`, &claim1); err != nil {
		fmt.Printf(`failed to retrieve claim1: %s`, err)
		return
	}
	if err := tok.Get(`claim2`, &claim2); err != nil {
		fmt.Printf(`failed to retrieve claim2: %s`, err)
		return
	}
	_ = claim1
	_ = claim2

	// However, it is possible to globally specify that a private
	// claim should be parsed into a custom type.
	// In the sample below `claim2` is to be an instance of time.Time
	jwt.RegisterCustomField(`claim2`, time.Time{})

	tok = jwt.New()
	if err := json.Unmarshal([]byte(`{"claim2":"2022-05-16T07:35:56+00:00"}`), tok); err != nil {
		fmt.Printf(`failed to parse token: %s`, err)
		return
	}

	var claim2AsTime time.Time
	if err := tok.Get(`claim2`, &claim2AsTime); err != nil {
		fmt.Printf(`failed to get private claim "claim2": %s`, err)
		return
	}

	_ = v
	_ = ok

	// OUTPUT:
}
