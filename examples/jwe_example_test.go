package examples_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"

	"github.com/lestrrat-go/jwx/v2/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
)

func exampleGenPayload() (*rsa.PrivateKey, []byte, error) {
	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	payload := []byte("Lorem Ipsum")

	encrypted, err := jwe.Encrypt(payload, jwe.WithKey(jwa.RSA1_5, &privkey.PublicKey), jwe.WithContentEncryption(jwa.A128CBC_HS256))
	if err != nil {
		return nil, nil, err
	}
	return privkey, encrypted, nil
}

func ExampleJWE_Decrypt() {
	privkey, encrypted, err := exampleGenPayload()
	if err != nil {
		log.Printf("failed to generate encrypted payload: %s", err)
		return
	}

	decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.RSA1_5, privkey))
	if err != nil {
		log.Printf("failed to decrypt: %s", err)
		return
	}

	if string(decrypted) != "Lorem Ipsum" {
		log.Printf("WHAT?!")
		return
	}
	// OUTPUT:
}

func ExampleJWE_ComplexDecrypt() {
	// WARNING: THIS USAGE IS NOT FOR A CASUAL USER. ONLY use it when you must.
	// Only use it when you understand how JWE is supposed to work. Only use it
	// when you understand the inner workings of this code.

	// In this example, the caller wants to determine the key to use by checking
	// the value of a protected header called `jwx-hints`.

	const payload = "Hello, World!"

	privkey, err := jwxtest.GenerateRsaKey()
	if err != nil {
		fmt.Printf("failed to generate key: %s\n", err)
		return
	}

	// First we will create a sample JWE payload
	protected := jwe.NewHeaders()
	protected.Set(`jwx-hints`, `foobar`) // in real life this would a more meaningful value
	encrypted, err := jwe.Encrypt(
		[]byte(payload),
		jwe.WithKey(jwa.RSA_OAEP, privkey.PublicKey),
		jwe.WithProtectedHeaders(protected),
	)
	if err != nil {
		fmt.Printf("failed to encrypt message\n")
		return
	}

	// The party responsible to determining the key is the jwe.KeyProvider hook.
	//
	// Here we are using a function turned into an interface for brevity, but in real life
	// I would personally recommend creating a real type for your specific needs
	// instead of passing adhoc closures. YMMV.
	kp := func(ctx context.Context, sink jwe.KeySink, _ jwe.Recipient, msg *jwe.Message) error {
		var hint string
		if err := msg.ProtectedHeaders().Get(`jwx-hints`, &hint); err != nil {
			return fmt.Errorf(`could not find "jwx-hints" field`)
		}

		if hint == `foobar` {
			// This is where we are setting the key to be used.
			//
			// In real life you would look up the key or something.
			// Here we just assign the key to use.
			//
			// You may opt to set both the algorithm and key here as well.
			// BUT BE CAREFUL so that you don't accidentally create a
			// vulnerability
			sink.Key(jwa.RSA_OAEP, privkey)
			return nil
		}

		// If there were errors, just return it, and the whole jwe.Decrypt will fail.
		return fmt.Errorf(`invalid value for jwx-hints: %s`, hint)
	}

	// Calling jwe.Decrypt with the extra argument of jwe.WithPostParser().
	// Here we pass a nil key to jwe.Decrypt, because the PostParser will be
	// determining the key to use when its PostParse() method is called
	decrypted, err := jwe.Decrypt(encrypted, jwe.WithKeyProvider(jwe.KeyProviderFunc(kp)))
	if err != nil {
		fmt.Printf("failed to decrypt message: %s\n", err)
		return
	}

	if string(decrypted) != payload {
		fmt.Printf("wrong decrypted payload: %s\n", decrypted)
		return
	}

	// OUTPUT:
}
