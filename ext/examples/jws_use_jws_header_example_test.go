package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
)

func Example_jws_use_jws_header() {
	key, err := jwk.Import[jwk.Key]([]byte(`abracadabra`))
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
