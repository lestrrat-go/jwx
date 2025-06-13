package jwsbb

import (
	"crypto"
	"crypto/rand"
	"fmt"
)

// cryptosign is a low-level function that signs a payload using a crypto.Signer.
// If hash is crypto.Hash(0), the payload is signed directly without hashing.
// Otherwise, the payload is hashed using the specified hash function before signing.
func cryptosign(signer crypto.Signer, payload []byte, hash crypto.Hash, opts crypto.SignerOpts) ([]byte, error) {
	var digest []byte
	if hash == crypto.Hash(0) {
		digest = payload
	} else {
		h := hash.New()
		if _, err := h.Write(payload); err != nil {
			return nil, fmt.Errorf(`failed to write payload to hash: %w`, err)
		}
		digest = h.Sum(nil)
	}
	return signer.Sign(rand.Reader, digest, opts)
}

// SignCryptoSigner generates a signature using a crypto.Signer interface.
// This function is useful for integrating with hardware security modules, smart cards,
// and other implementations of the crypto.Signer interface.
//
// Parameters:
//   - signer: The crypto.Signer implementation (must not be nil)
//   - raw: The pre-computed signing input (typically header.payload)
//   - h: The hash function to use (use crypto.Hash(0) for direct signing)
//   - opts: Additional signing options specific to the signature algorithm
//
// Returns the signature bytes or an error if signing fails.
func SignCryptoSigner(signer crypto.Signer, raw []byte, h crypto.Hash, opts crypto.SignerOpts) ([]byte, error) {
	if signer == nil {
		return nil, fmt.Errorf("jwsbb.SignCryptoSignerRaw: signer is nil")
	}
	return cryptosign(signer, raw, h, opts)
}
