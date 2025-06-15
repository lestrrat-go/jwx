package jwsbb

import (
	"crypto"
	"fmt"
)

// Sign generates a JWS signature using the specified key and algorithm.
//
// This function loads the signer registered in the hwsbb package _ONLY_.
// It does not support custom signers that the user might have registered.
func Sign(key any, alg string, payload []byte) ([]byte, error) {
	switch alg {
	case "HS256", "HS384", "HS512":
		h, err := HMACHashFuncFor(alg)
		if err != nil {
			return nil, fmt.Errorf(`jwsbb.Sign: failed to get hash function for %s: %w`, alg, err)
		}

		var hmackey []byte
		if err := toHMACKey(&hmackey, key); err != nil {
			return nil, fmt.Errorf(`jwsbb.Sign: %w`, err)
		}
		return SignHMAC(hmackey, payload, h)
	case "EdDSA":
		signer, err := eddsaGetSigner(key)
		if err != nil {
			return nil, fmt.Errorf(`jws.EdDSASigner: %w`, err)
		}

		return SignCryptoSigner(signer, payload, crypto.Hash(0), crypto.Hash(0))

	}

	return nil, fmt.Errorf(`jwsbb.Sign: unsupported algorithm %s`, alg)
}
