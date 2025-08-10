package jwsbb

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"

	"github.com/lestrrat-go/dsig"
	"github.com/lestrrat-go/jwx/v3/internal/keyconv"
)

// Verify verifies a JWS signature using the specified key and algorithm.
//
// This function loads the verifier registered in the jwsbb package _ONLY_.
// It does not support custom verifiers that the user might have registered.
func Verify(key any, alg string, payload, signature []byte) error {
	if _, ok := hmacHashFuncs[alg]; ok {
		return dispatchHMACVerify(key, alg, payload, signature)
	} else if _, ok := rsaHashFuncs[alg]; ok {
		return dispatchRSAVerify(key, alg, payload, signature)
	} else if _, ok := ecdsaHashFuncs[alg]; ok {
		return dispatchECDSAVerify(key, alg, payload, signature)
	} else if alg == edDSA {
		return dispatchEdDSAVerify(key, alg, payload, signature)
	}

	return fmt.Errorf(`jwsbb.Verify: unsupported signature algorithm %q`, alg)
}

func dispatchHMACVerify(key any, alg string, payload, signature []byte) error {
	dsigAlg, ok := jwsTodsigAlgMapping[alg]
	if !ok {
		return fmt.Errorf(`jwsbb.Verify: unsupported signature algorithm %q`, alg)
	}

	var hmackey []byte
	if err := keyconv.ByteSliceKey(&hmackey, key); err != nil {
		return fmt.Errorf(`jwsbb.Verify: invalid key type %T. []byte is required: %w`, key, err)
	}

	return dsig.Verify(hmackey, dsigAlg, payload, signature)
}

func dispatchRSAVerify(key any, alg string, payload, signature []byte) error {
	dsigAlg, ok := jwsTodsigAlgMapping[alg]
	if !ok {
		return fmt.Errorf(`jwsbb.Verify: unsupported signature algorithm %q`, alg)
	}

	// Try crypto.Signer first (dsig can handle it directly)
	if signer, ok := key.(crypto.Signer); ok {
		// Verify it's an RSA key
		if _, ok := signer.Public().(*rsa.PublicKey); ok {
			return dsig.Verify(signer, dsigAlg, payload, signature)
		}
	}

	// Fall back to concrete key types
	var pubkey *rsa.PublicKey
	if err := keyconv.RSAPublicKey(&pubkey, key); err != nil {
		return fmt.Errorf(`jwsbb.Verify: invalid key type %T. *rsa.PublicKey is required: %w`, key, err)
	}

	return dsig.Verify(pubkey, dsigAlg, payload, signature)
}

func dispatchECDSAVerify(key any, alg string, payload, signature []byte) error {
	dsigAlg, ok := jwsTodsigAlgMapping[alg]
	if !ok {
		return fmt.Errorf(`jwsbb.Verify: unsupported signature algorithm %q`, alg)
	}

	// Try crypto.Signer first (dsig can handle it directly)
	if signer, ok := key.(crypto.Signer); ok {
		// Verify it's an ECDSA key
		if _, ok := signer.Public().(*ecdsa.PublicKey); ok {
			return dsig.Verify(signer, dsigAlg, payload, signature)
		}
	}

	// Fall back to concrete key types
	var pubkey *ecdsa.PublicKey
	if err := keyconv.ECDSAPublicKey(&pubkey, key); err != nil {
		return fmt.Errorf(`jwsbb.Verify: invalid key type %T. *ecdsa.PublicKey is required: %w`, key, err)
	}

	return dsig.Verify(pubkey, dsigAlg, payload, signature)
}

func dispatchEdDSAVerify(key any, _ string, payload, signature []byte) error {
	// Try crypto.Signer first (dsig can handle it directly)
	if signer, ok := key.(crypto.Signer); ok {
		// Verify it's an EdDSA key
		if _, ok := signer.Public().(ed25519.PublicKey); ok {
			return dsig.Verify(signer, dsig.EdDSA, payload, signature)
		}
	}

	// Fall back to concrete key types
	var pubkey ed25519.PublicKey
	if err := keyconv.Ed25519PublicKey(&pubkey, key); err != nil {
		return fmt.Errorf(`jwsbb.Verify: invalid key type %T. ed25519.PublicKey is required: %w`, key, err)
	}

	return dsig.Verify(pubkey, dsig.EdDSA, payload, signature)
}
