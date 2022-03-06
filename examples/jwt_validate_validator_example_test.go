package examples_test

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

func ExampleJWT_ValidateValidator() {
	validator := jwt.ValidatorFunc(func(_ context.Context, t jwt.Token) error {
		if t.IssuedAt().Month() != 8 {
			return jwt.NewValidationError(errors.New(`tokens are only valid if issued during August!`))
		}
		return nil
	})

	tok, err := jwt.NewBuilder().
		Issuer(`github.com/lestrrat-go/jwx`).
		IssuedAt(time.Unix(aLongLongTimeAgo, 0)).
		Build()
	if err != nil {
		fmt.Printf("failed to build token: %s\n", err)
		return
	}

	err = jwt.Validate(tok, jwt.WithValidator(validator))
	if err == nil {
		fmt.Printf("token should fail validation\n")
		return
	}
	fmt.Printf("%s\n", err)
	// OUTPUT:
	// tokens are only valid if issued during August!
}
