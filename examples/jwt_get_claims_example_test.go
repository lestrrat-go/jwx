package examples_test

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func ExampleJWT_GetClaims() {
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
	var _ time.Time = tok.IssuedAt()
	var _ string = tok.Issuer()
	var _ string = tok.Subject()

	// But you can also get them via the generic `.Get()` method.
	// However, you would need to decide for yourself what the
	// return type is. If you don't need the exact type, you could
	// use interface{}, or you could use the specific time.Time
	// type
	//
	// For the key name you could also use jwt.IssuedAtKey constant
	var iat time.Time
	_ = tok.Get(`iat`, &iat)

	// var iat interface{} would also work, but you would need to
	// convert the type if you need time.Time specific behavior

	// Private claims
	var dummy interface{}
	_ = tok.Get(`claim1`, &dummy)
	_ = tok.Get(`claim2`, &dummy)
	_ = tok.Get(`claim3`, &dummy)

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
	var claim2 time.Time
	if err := tok.Get(`claim2`, &claim2); err != nil {
		fmt.Printf("failed to get private claim \"claim2\": %s\n", err)
		return
	}

	// It's also possible to specify a custom decoder for a private claim.
	// For example, in the case of `claim3`, it needs to call `jwk.ParseKey`
	// which returns an interface that can't be instantiated like the
	// `time.Time` value for `claim2`.
	jwt.RegisterCustomField(`claim3`, jwt.CustomDecodeFunc(func(data []byte) (interface{}, error) {
		return jwk.ParseKey(data)
	}))

	tok = jwt.New()
	if err := json.Unmarshal([]byte(`{"claim3": {"kty": "oct", "alg":"A128KW", "k":"GawgguFyGrWKav7AX4VKUg"}}`), tok); err != nil {
		fmt.Printf(`failed to parse token: %s`, err)
		return
	}
	var claim3 jwk.Key
	if err := tok.Get(`claim3`, &claim3); err != nil {
		fmt.Printf("failed to get private claim \"claim3\": %s\n", err)
		return
	}

	// OUTPUT:
}
