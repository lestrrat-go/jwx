package examples_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"

	"github.com/lestrrat-go/jwx/internal/jwxtest"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe"
	"github.com/pkg/errors"
)

func ExampleJWE_Encrypt() {
	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("failed to generate private key: %s", err)
		return
	}

	payload := []byte("Lorem Ipsum")

	encrypted, err := jwe.Encrypt(payload, jwa.RSA1_5, &privkey.PublicKey, jwa.A128CBC_HS256, jwa.NoCompress)
	if err != nil {
		log.Printf("failed to encrypt payload: %s", err)
		return
	}
	_ = encrypted
	// OUTPUT:
}

func exampleGenPayload() (*rsa.PrivateKey, []byte, error) {
	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	payload := []byte("Lorem Ipsum")

	encrypted, err := jwe.Encrypt(payload, jwa.RSA1_5, &privkey.PublicKey, jwa.A128CBC_HS256, jwa.NoCompress)
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

	decrypted, err := jwe.Decrypt(encrypted, jwa.RSA1_5, privkey)
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
	// the value of a protected header. called `jwx-hints`.

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
		jwa.RSA_OAEP,
		privkey.PublicKey,
		jwa.A256GCM,
		jwa.NoCompress,
		jwe.WithProtectedHeaders(protected),
	)
	if err != nil {
		fmt.Printf("failed to encrypt message\n")
		return
	}

	// Here we pass a nil key, because we will be determining the key to use later.
	// The party responsible to determining the key is the jwe.PostParse hook.
	// Here we are using a function turned into an interface for brevity, but in real life
	// I would personally recommend creating a real type for your specific needs
	// instead of passing adhoc functions
	pp := func(ctx jwe.DecryptCtx) error {
		msg := ctx.Message()
		rawhint, _ := msg.ProtectedHeaders().Get(`jwx-hints`)
		//nolint:forcetypeassert
		hint := rawhint.(string)
		switch hint {
		case `foobar`:
			// in real life you would look up the key or something.
			// here we just assign the key to use.
			ctx.SetKey(privkey)
		default:
			return errors.Errorf(`invalid value for jwx-hints: %s`, hint)
		}
		return nil
	}
	decrypted, err := jwe.Decrypt(encrypted, jwa.RSA_OAEP, nil, jwe.WithPostParser(jwe.PostParseFunc(pp)))
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
