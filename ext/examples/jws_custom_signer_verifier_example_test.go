package examples_test

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/sign/ed25519"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
)

func Example_jws_custom_signer_verifier() {
	if err := jws.RegisterSigner(jwa.EdDSA(), CirclEdDSASigner{}); err != nil {
		fmt.Printf(`failed to register signer: %s`, err)
		return
	}

	if err := jws.RegisterVerifier(jwa.EdDSA(), CirclEdDSAVerifier{}); err != nil {
		fmt.Printf(`failed to register verifier: %s`, err)
		return
	}
	pubkey, privkey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf(`failed to generate keys: %s`, err)
		return
	}

	const payload = "Lorem Ipsum"
	signed, err := jws.Sign([]byte(payload), jws.WithKey(jwa.EdDSA(), privkey))
	if err != nil {
		fmt.Printf(`failed to generate signed message: %s`, err)
		return
	}

	verified, err := jws.Verify(signed, jws.WithKey(jwa.EdDSA(), pubkey))
	if err != nil {
		fmt.Printf(`failed to verify signed message: %s`, err)
		return
	}

	if string(verified) != payload {
		fmt.Printf(`got invalid payload: %s`, verified)
		return
	}

	// OUTPUT:
	// Custom signer called
	// Custom verifier called
}

type CirclEdDSASigner struct{}

// Sign implements the jws.Signer interface for Circl's EdDSA signer.
//
// Signer is a relatively low-level API. It receives multiple parameters because of this.
//
// One thing you should do in your signer is to check the type of the key passed in.
// We have no way of constricting the type of key that is passed in without knowing
// the implementation details of your custom signer, and thus we cannot guarantee that
// users will pass in the correct type of key.
//
// Those implementing the jws.Signer interface could construct the buffer to be signed
// themselves and generate the signature, but it is often easier to use the jwsbb.Sign
// function, which takes care of the constructiion. In this example, we would like to
// tell jwsbb.Sign to construct the buffer and generate the signature using ed25519.Sign,
// but since the function signatures do not match, we are providing an adapter
// that implements the dsig.Signer interface.
//
// If you need to construct the buffer yourself, you can do so by using the
// jwsbb.SignBuffer() function in combination with the jwsbb.SignRaw() function.
func (CirclEdDSASigner) Sign(key any, payload []byte) ([]byte, error) {
	fmt.Println("Custom signer called")
	privkey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf(`jws.CirclEdDSASigner: invalid key type %T. ed25519.PrivateKey is required`, key)
	}
	return ed25519.Sign(privkey, payload), nil
}

type CirclEdDSAVerifier struct{}

// Verify implements the jws.Verifier interface for Circl's EdDSA verifier.
//
// See the comments for CirclEdDSASigner.Sign for more information on what this function does.
func (CirclEdDSAVerifier) Verify(key any, payload, signature []byte) error {
	fmt.Println("Custom verifier called")
	pubkey, ok := key.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf(`jws.CirclECDSASignerVerifier: invalid key type %T. ed25519.PublicKey is required`, key)
	}

	if ed25519.Verify(pubkey, payload, signature) {
		return nil
	}
	return fmt.Errorf(`failed to verify EdDSA signature`)
}
