//go:build jwx_dilithium
// +build jwx_dilithium

package jws

import (
	"crypto"
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/sign/dilithium/mode2"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/cloudflare/circl/sign/dilithium/mode5"
	"github.com/lestrrat-go/jwx/v3/jwa"
)

func init() {
	for _, alg := range []jwa.SignatureAlgorithm{jwa.CRYDI2(), jwa.CRYDI3(), jwa.CRYDI5()} {
		RegisterSigner(alg, func(alg jwa.SignatureAlgorithm) SignerFactory {
			return SignerFactoryFn(func() (Signer, error) {
				return newDilithiumSigner(alg), nil
			})
		}(alg))

		RegisterVerifier(alg, func(alg jwa.SignatureAlgorithm) VerifierFactory {
			return VerifierFactoryFn(func() (Verifier, error) {
				return newDilithiumVerifier(alg), nil
			})
		}(alg))
	}
}

type dilithiumSigner struct {
	alg  jwa.SignatureAlgorithm
	sign func(payload []byte, key interface{}) ([]byte, error)
}

func (s dilithiumSigner) Algorithm() jwa.SignatureAlgorithm {
	return s.alg
}

func (s dilithiumSigner) Sign(payload []byte, key interface{}) ([]byte, error) {
	return s.sign(payload, key)
}

func newDilithiumSigner(alg jwa.SignatureAlgorithm) Signer {
	switch alg {
	case jwa.CRYDI2():
		return dilithiumSigner{
			alg:  alg,
			sign: dilithiumMode2Sign,
		}
	case jwa.CRYDI3():
		return dilithiumSigner{
			alg:  alg,
			sign: dilithiumMode3Sign,
		}
	case jwa.CRYDI5():
		return dilithiumSigner{
			alg:  alg,
			sign: dilithiumMode5Sign,
		}
	default:
		return nil
	}
}

func dilithiumMode2Sign(payload []byte, key interface{}) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf(`missing private key while signing payload`)
	}

	privKey, ok := key.(*mode2.PrivateKey)
	if !ok {
		return nil, fmt.Errorf(`invalid private key type %T`, key)
	}

	sig, err := privKey.Sign(rand.Reader, payload, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf(`failed to sign payload: %w`, err)
	}

	return sig, nil
}

func dilithiumMode3Sign(payload []byte, key interface{}) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf(`missing private key while signing payload`)
	}

	privKey, ok := key.(*mode3.PrivateKey)
	if !ok {
		return nil, fmt.Errorf(`invalid private key type %T`, key)
	}

	sig, err := privKey.Sign(rand.Reader, payload, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf(`failed to sign payload: %w`, err)
	}

	return sig, nil
}

func dilithiumMode5Sign(payload []byte, key interface{}) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf(`missing private key while signing payload`)
	}

	privKey, ok := key.(*mode5.PrivateKey)
	if !ok {
		return nil, fmt.Errorf(`invalid private key type %T`, key)
	}

	sig, err := privKey.Sign(rand.Reader, payload, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf(`failed to sign payload: %w`, err)
	}

	return sig, nil
}

func newDilithiumVerifier(alg jwa.SignatureAlgorithm) Verifier {
	switch alg {
	case jwa.CRYDI2():
		return VerifierFunc(dilithiumMode2Verify)
	case jwa.CRYDI3():
		return VerifierFunc(dilithiumMode3Verify)
	case jwa.CRYDI5():
		return VerifierFunc(dilithiumMode5Verify)
	default:
		return nil
	}
}

func dilithiumMode2Verify(payload, sig []byte, key interface{}) error {
	if key == nil {
		return fmt.Errorf(`missing public key while verifying payload`)
	}

	pubkey, ok := key.(*mode2.PublicKey)
	if !ok {
		return fmt.Errorf(`invalid public key type %T`, key)
	}

	if !mode2.Verify(pubkey, payload, sig) {
		return fmt.Errorf(`failed to verify payload`)
	}
	return nil
}

func dilithiumMode3Verify(payload, sig []byte, key interface{}) error {
	if key == nil {
		return fmt.Errorf(`missing public key while verifying payload`)
	}

	pubkey, ok := key.(*mode3.PublicKey)
	if !ok {
		return fmt.Errorf(`invalid public key type %T`, key)
	}

	if !mode3.Verify(pubkey, payload, sig) {
		return fmt.Errorf(`failed to verify payload`)
	}
	return nil
}

func dilithiumMode5Verify(payload, sig []byte, key interface{}) error {
	if key == nil {
		return fmt.Errorf(`missing public key while verifying payload`)
	}

	pubkey, ok := key.(*mode5.PublicKey)
	if !ok {
		return fmt.Errorf(`invalid public key type %T`, key)
	}

	if !mode5.Verify(pubkey, payload, sig) {
		return fmt.Errorf(`failed to verify payload`)
	}
	return nil
}
