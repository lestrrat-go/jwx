package examples_test

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func Example_jwt_get_claims() {
	tok, err := jwt.NewBuilder().
		IssuedAt(time.Now()).
		Issuer(`github.com/lestrrat-go/jwx`).
		Subject(`example`).
		Claim(`claim1`, `value1`).
		Claim(`claim2`, `2022-05-16T07:35:56+00:00`).
		Claim(`claim3`, `{"kty": "oct", "alg":"A128KW", "k":"GawgguFyGrWKav7AX4VKUg"}`).
		Build()
	if err != nil {
		fmt.Printf("failed to build token: %s\n", err)
		return
	}

	// Pre-defined fields have typed accessors.
	iat, _ := tok.IssuedAt()
	iss, _ := tok.Issuer()
	sub, _ := tok.Subject()

	var _ time.Time = iat
	var _ string = iss
	var _ string = sub

	// But you can also get them via the generic `.Field()` method.
	// However, the return type is `any`, so you would need to
	// do a type assertion if you need the specific type.
	//
	// For the key name you could also use jwt.IssuedAtKey constant
	iatV, _ := tok.Field(`iat`)
	_ = iatV

	// Private claims
	dummy1, _ := tok.Field(`claim1`)
	dummy2, _ := tok.Field(`claim2`)
	dummy3, _ := tok.Field(`claim3`)
	_, _, _ = dummy1, dummy2, dummy3

	// However, it is possible to globally specify that a private
	// claim should be parsed into a custom type.
	// In the sample below `claim2` is to be an instance of time.Time
	jwt.RegisterCustomField(`claim2`, time.Time{})

	tok = jwt.New()
	if err := json.Unmarshal([]byte(`{"claim2":"2022-05-16T07:35:56+00:00"}`), tok); err != nil {
		fmt.Printf(`failed to parse token: %s`, err)
		return
	}

	// now you can use the exact type
	claim2V, ok := tok.Field(`claim2`)
	if !ok {
		fmt.Printf("failed to get private claim \"claim2\"\n")
		return
	}
	claim2 := claim2V.(time.Time)
	_ = claim2

	// It's also possible to specify a custom decoder for a private claim.
	// For example, in the case of `claim3`, it needs to call `jwk.ParseKey`
	// which returns an interface that can't be instantiated like the
	// `time.Time` value for `claim2`.
	jwt.RegisterCustomField(`claim3`, jwt.CustomDecodeFunc(func(data []byte) (any, error) {
		return jwk.ParseKey[jwk.Key](data)
	}))

	tok = jwt.New()
	if err := json.Unmarshal([]byte(`{"claim3": {"kty": "oct", "alg":"A128KW", "k":"GawgguFyGrWKav7AX4VKUg"}}`), tok); err != nil {
		fmt.Printf(`failed to parse token: %s`, err)
		return
	}
	claim3V, ok := tok.Field(`claim3`)
	if !ok {
		fmt.Printf("failed to get private claim \"claim3\"\n")
		return
	}
	claim3 := claim3V.(jwk.Key)
	_ = claim3

	// OUTPUT:
}
