package examples_test

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/sign/ed25519"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
)

type CirclEdDSASignerVerifier struct{}

func NewCirclEdDSASigner() (jws.Signer, error) {
	return &CirclEdDSASignerVerifier{}, nil
}

func NewCirclEdDSAVerifier() (jws.Verifier, error) {
	return &CirclEdDSASignerVerifier{}, nil
}

func (s CirclEdDSASignerVerifier) Algorithm() jwa.SignatureAlgorithm {
	return jwa.EdDSA
}

func (s CirclEdDSASignerVerifier) Sign(payload []byte, keyif interface{}) ([]byte, error) {
	switch key := keyif.(type) {
	case ed25519.PrivateKey:
		return ed25519.Sign(key, payload), nil
	default:
		return nil, fmt.Errorf(`invalid key type %T`, keyif)
	}
}

func (s CirclEdDSASignerVerifier) Verify(payload []byte, signature []byte, keyif interface{}) error {
	switch key := keyif.(type) {
	case ed25519.PublicKey:
		if ed25519.Verify(key, payload, signature) {
			return nil
		}
		return fmt.Errorf(`failed to verify EdDSA signature`)
	default:
		return fmt.Errorf(`invalid key type %T`, keyif)
	}
}

func ExampleJWS_CustomSignerVerifier() {
	// This example shows how to register external jws.Signer / jws.Verifier for
	// a given algorithm.
	jws.RegisterSigner(jwa.EdDSA, jws.SignerFactoryFn(NewCirclEdDSASigner))
	jws.RegisterVerifier(jwa.EdDSA, jws.VerifierFactoryFn(NewCirclEdDSAVerifier))

	pubkey, privkey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf(`failed to generate keys: %s`, err)
		return
	}

	const payload = "Lorem Ipsum"
	signed, err := jws.Sign([]byte(payload), jws.WithKey(jwa.EdDSA, privkey))
	if err != nil {
		fmt.Printf(`failed to generate signed message: %s`, err)
		return
	}

	verified, err := jws.Verify(signed, jws.WithKey(jwa.EdDSA, pubkey))
	if err != nil {
		fmt.Printf(`failed to verify signed message: %s`, err)
		return
	}

	if string(verified) != payload {
		fmt.Printf(`got invalid payload: %s`, verified)
		return
	}

	// OUTPUT:
}
