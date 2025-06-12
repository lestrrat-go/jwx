package examples_test

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/sign/ed25519"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jws/jwsbb"
)

func Example_jws_custom_signer_verifier() {
	// This example shows how to register external jws.Signer / jws.Verifier for
	// a given algorithm.

	for _, useLegacy := range []bool{false, true} {
		if useLegacy {
			// Legacy signer/verifier registration. DO NOT USE THIS IN NEW CODE.
			jws.RegisterSigner(jwa.EdDSA(), jws.SignerFactoryFn(LegacyNewCirclEdDSASigner))
			jws.RegisterVerifier(jwa.EdDSA(), jws.VerifierFactoryFn(LegacyNewCirclEdDSAVerifier))
		} else {
			// Newer way of registering a custom signer/verifier
			jws.RegisterSigner(jwa.EdDSA(), CirclECDSASigner{})
			jws.RegisterVerifier(jwa.EdDSA(), CirclECDSAVerifier{})
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
	}
	// OUTPUT:
	// Custom signer called
	// Custom verifier called
	// Custom signer called (legacy)
	// Custom verifier called (legacy)
}

type CirclECDSASigner struct{}

func (CirclECDSASigner) Algorithm() jwa.SignatureAlgorithm {
	return jwa.EdDSA()
}

type CirclECDSASignerAdapter struct{}

func (CirclECDSASignerAdapter) Sign(key ed25519.PrivateKey, payload []byte) ([]byte, error) {
	return ed25519.Sign(key, payload), nil
}

// Do implements the jws.Signer interface for Circl's EdDSA signer.
//
// Signer2 is a relatively low-level API. It receives multiple parameters because of this.
//
// One thing you should do in your signer is to check the type of the key passed in.
// We have no way of constricting the type of key that is passed in without knowing
// the implementation details of your custom signer, and thus we cannot guarantee that
// users will pass in the correct type of key.
//
// Those implementing the jws.Signer2 interface can construct the buffer to be signed
// themselves and generate the signature, but it is often easier to use the jwsbb.Sign
// function, which takes care of the constructiion. In this example, we would like to
// tell jwsbb.Sign to construct the buffer and generate the signature using ed25519.Sign,
// but since the function signatures do not match, we are providing an adapter
// that implements the jwsbb.Signer interface.
func (CirclECDSASigner) Do(payload []byte, protected []byte, encoder jws.Base64Encoder, encodePayload bool, key any) ([]byte, error) {
	fmt.Println("Custom signer called")
	privkey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf(`jws.CirclECDSASignerVerifier: invalid key type %T. ed25519.PrivateKey is required`, key)
	}

	return jwsbb.Sign(privkey, payload, protected, CirclECDSASignerAdapter{}, encoder, encodePayload)
}

type CirclECDSAVerifier struct{}

func (CirclECDSAVerifier) Algorithm() jwa.SignatureAlgorithm {
	return jwa.EdDSA()
}

type CirclECDSAVerifierAdapter struct{}

func (CirclECDSAVerifierAdapter) Verify(key ed25519.PublicKey, payload []byte, signature []byte) error {
	if ed25519.Verify(key, payload, signature) {
		return nil
	}
	return fmt.Errorf(`failed to verify EdDSA signature`)
}

// Do implements the jws.Verifier interface for Circl's EdDSA verifier.
//
// See the comments for CirclECDSASigner.Do for more information on what this function does.
func (CirclECDSAVerifier) Do(payload []byte, protected []byte, signature []byte, encoder jws.Base64Encoder, encodePayload bool, key any) error {
	fmt.Println("Custom verifier called")
	pubkey, ok := key.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf(`jws.CirclECDSASignerVerifier: invalid key type %T. ed25519.PublicKey is required`, key)
	}

	return jwsbb.Verify(pubkey, payload, protected, signature, CirclECDSAVerifierAdapter{}, encoder, encodePayload)
}

type LegacyCirclEdDSASignerVerifier struct{}

func LegacyNewCirclEdDSASigner() (jws.Signer, error) {
	return &LegacyCirclEdDSASignerVerifier{}, nil
}

func LegacyNewCirclEdDSAVerifier() (jws.Verifier, error) {
	return &LegacyCirclEdDSASignerVerifier{}, nil
}

func (s LegacyCirclEdDSASignerVerifier) Algorithm() jwa.SignatureAlgorithm {
	return jwa.EdDSA()
}

func (s LegacyCirclEdDSASignerVerifier) Sign(payload []byte, keyif interface{}) ([]byte, error) {
	fmt.Println("Custom signer called (legacy)")
	switch key := keyif.(type) {
	case ed25519.PrivateKey:
		return ed25519.Sign(key, payload), nil
	default:
		return nil, fmt.Errorf(`invalid key type %T`, keyif)
	}
}

func (s LegacyCirclEdDSASignerVerifier) Verify(payload []byte, signature []byte, keyif interface{}) error {
	fmt.Println("Custom verifier called (legacy)")
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
