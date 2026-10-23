package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func Example_jws_use_jws_header() {
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

	// A JWS in compact format has exactly one signature, so index 0 is that
	// signature. A JSON JWS can have several, and jws.Parse verifies none of
	// them, so do not pick an entry by position in that case.
	kid, ok := msg.Signatures()[0].ProtectedHeaders().KeyID()
	if !ok {
		fmt.Printf("failed to get key ID from protected headers")
		return
	}
	fmt.Printf("%q\n", kid)
	// OUTPUT:
	// "secret-key"
}
