package examples_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/v3/internal/json"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
)

func ExampleJWE_SignWithHeaders() {
	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("failed to create private key: %s\n", err)
		return
	}
	const payload = "Lorem ipsum"

	hdrs := jwe.NewHeaders()
	hdrs.Set(`x-example`, true)
	encrypted, err := jwe.Encrypt([]byte(payload), jwe.WithKey(jwa.RSA_OAEP(), privkey.PublicKey, jwe.WithPerRecipientHeaders(hdrs)))
	if err != nil {
		fmt.Printf("failed to encrypt payload: %s\n", err)
		return
	}

	msg, err := jwe.Parse(encrypted)
	if err != nil {
		fmt.Printf("failed to parse message: %s\n", err)
		return
	}

	// NOTE: This is a bit tricky. Even though we specified a per-recipient
	// header when executing jwe.Encrypt, the headers end up being in the
	// global protected headers section. This is... by the books. JWE
	// in Compact serialization asks us to shove the per-recipient
	// headers in the protected header section, because there is nowhere
	// else to store this information.
	//
	// If this were a full JWE JSON message, you might have to juggle
	// between the global protected headers, global unprotected headers,
	// and per-recipient unprotected headers
	json.NewEncoder(os.Stdout).Encode(msg.ProtectedHeaders())

	// OUTPUT:
	// {"alg":"RSA-OAEP","enc":"A256GCM","x-example":true}
}
