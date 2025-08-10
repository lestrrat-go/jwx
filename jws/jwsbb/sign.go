package jwsbb

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"io"

	"github.com/lestrrat-go/dsig"
	"github.com/lestrrat-go/jwx/v3/internal/keyconv"
)

// Sign generates a JWS signature using the specified key and algorithm.
//
// This function loads the signer registered in the jwsbb package _ONLY_.
// It does not support custom signers that the user might have registered.
//
// rr is an io.Reader that provides randomness for signing. If rr is nil, it defaults to rand.Reader.
// Not all algorithms require this parameter, but it is included for consistency.
// 99% of the time, you can pass nil for rr, and it will work fine.
func Sign(key any, alg string, payload []byte, rr io.Reader) ([]byte, error) {
	if _, ok := hmacHashFuncs[alg]; ok {
		return dispatchHMACSign(key, alg, payload)
	} else if _, ok := rsaHashFuncs[alg]; ok {
		return dispatchRSASign(key, alg, payload, rr)
	} else if _, ok := ecdsaHashFuncs[alg]; ok {
		return dispatchECDSASign(key, alg, payload, rr)
	} else if alg == edDSA {
		return dispatchEdDSASign(key, alg, payload, rr)
	}

	return nil, fmt.Errorf(`jwsbb.Sign: unsupported signature algorithm %q`, alg)
}

func dispatchHMACSign(key any, alg string, payload []byte) ([]byte, error) {
	dsigAlg, ok := jwsTodsigAlgMapping[alg]
	if !ok {
		return nil, fmt.Errorf(`jwsbb.Sign: unsupported signature algorithm %q`, alg)
	}

	var hmackey []byte
	if err := keyconv.ByteSliceKey(&hmackey, key); err != nil {
		return nil, fmt.Errorf(`jwsbb.Sign: invalid key type %T. []byte is required: %w`, key, err)
	}

	return dsig.Sign(hmackey, dsigAlg, payload, nil)
}

func dispatchRSASign(key any, alg string, payload []byte, rr io.Reader) ([]byte, error) {
	dsigAlg, ok := jwsTodsigAlgMapping[alg]
	if !ok {
		return nil, fmt.Errorf(`jwsbb.Sign: unsupported signature algorithm %q`, alg)
	}

	// Try crypto.Signer first (dsig can handle it directly)
	if signer, ok := key.(crypto.Signer); ok {
		// Verify it's an RSA key
		if _, ok := signer.Public().(*rsa.PublicKey); ok {
			return dsig.Sign(signer, dsigAlg, payload, rr)
		}
	}

	// Fall back to concrete key types
	var privkey *rsa.PrivateKey
	if err := keyconv.RSAPrivateKey(&privkey, key); err != nil {
		return nil, fmt.Errorf(`jwsbb.Sign: invalid key type %T. *rsa.PrivateKey is required: %w`, key, err)
	}

	return dsig.Sign(privkey, dsigAlg, payload, rr)
}

func dispatchECDSASign(key any, alg string, payload []byte, rr io.Reader) ([]byte, error) {
	dsigAlg, ok := jwsTodsigAlgMapping[alg]
	if !ok {
		return nil, fmt.Errorf(`jwsbb.Sign: unsupported signature algorithm %q`, alg)
	}

	// Try crypto.Signer first (dsig can handle it directly)
	if signer, ok := key.(crypto.Signer); ok {
		// Verify it's an ECDSA key
		if _, ok := signer.Public().(*ecdsa.PublicKey); ok {
			return dsig.Sign(signer, dsigAlg, payload, rr)
		}
	}

	// Fall back to concrete key types
	var privkey *ecdsa.PrivateKey
	if err := keyconv.ECDSAPrivateKey(&privkey, key); err != nil {
		return nil, fmt.Errorf(`jwsbb.Sign: invalid key type %T. *ecdsa.PrivateKey is required: %w`, key, err)
	}

	return dsig.Sign(privkey, dsigAlg, payload, rr)
}

func dispatchEdDSASign(key any, _ string, payload []byte, rr io.Reader) ([]byte, error) {
	// Try crypto.Signer first (dsig can handle it directly)
	if signer, ok := key.(crypto.Signer); ok {
		// Verify it's an EdDSA key
		if _, ok := signer.Public().(ed25519.PublicKey); ok {
			return dsig.Sign(signer, dsig.EdDSA, payload, rr)
		}
	}

	// Fall back to concrete key types
	var privkey ed25519.PrivateKey
	if err := keyconv.Ed25519PrivateKey(&privkey, key); err != nil {
		return nil, fmt.Errorf(`jwsbb.Sign: invalid key type %T. ed25519.PrivateKey is required: %w`, key, err)
	}

	return dsig.Sign(privkey, dsig.EdDSA, payload, rr)
}
