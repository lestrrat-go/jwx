package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func ExampleJWS_UseJWSHeader() {
	key, err := jwk.Import([]byte(`abracadabra`))
	if err != nil {
		fmt.Printf(`failed to create new symmetric key: %s`, err)
		return
	}
	key.Set(jws.KeyIDKey, `secret-key`)

	tok, err := jwt.NewBuilder().
		Issuer(`github.com/lestrrat-go/jwx`).
		Build()
	if err != nil {
		fmt.Printf(`failed to build token: %s`, err)
		return
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256(), key))
	if err != nil {
		fmt.Printf(`failed to sign token: %s`, err)
		return
	}

	msg, err := jws.Parse(signed)
	if err != nil {
		fmt.Printf(`failed to parse serialized JWT: %s`, err)
		return
	}

	// While JWT enveloped with JWS in compact format only has 1 signature,
	// a generic JWS message may have multiple signatures. Therefore, we
	// need to access the first element
	kid, ok := msg.Signatures()[0].ProtectedHeaders().KeyID()
	if !ok {
		fmt.Printf("failed to get key ID from protected headers")
		return
	}
	fmt.Printf("%q\n", kid)
	// OUTPUT:
	// "secret-key"
}
