package jwsbb

import (
	"crypto/ed25519"
	"fmt"

	"github.com/lestrrat-go/dsig"
)

// validateEd25519KeyShape returns a non-nil error when key is an ed25519
// private/public key (value or pointer form) that is typed-nil or not the
// expected length, and nil for everything else — including non-ed25519 keys
// and well-formed ed25519 keys.
//
// Concrete ed25519 keys (and their pointer forms) satisfy crypto.Signer, but
// their Public() method panics ("slice bounds out of range" / nil pointer
// dereference) when the key is not exactly the right size. Dispatchers call
// this before any code path that may reach Public() — including the RSA/ECDSA
// dispatchers, where a cross-family ed25519 key would otherwise panic inside
// the crypto.Signer probe.
func validateEd25519KeyShape(key any) error {
	switch k := key.(type) {
	case ed25519.PrivateKey:
		if len(k) != ed25519.PrivateKeySize {
			return fmt.Errorf(`invalid ed25519.PrivateKey length %d, expected %d`, len(k), ed25519.PrivateKeySize)
		}
	case *ed25519.PrivateKey:
		if k == nil || len(*k) != ed25519.PrivateKeySize {
			return fmt.Errorf(`invalid *ed25519.PrivateKey, expected length %d`, ed25519.PrivateKeySize)
		}
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return fmt.Errorf(`invalid ed25519.PublicKey length %d, expected %d`, len(k), ed25519.PublicKeySize)
		}
	case *ed25519.PublicKey:
		if k == nil || len(*k) != ed25519.PublicKeySize {
			return fmt.Errorf(`invalid *ed25519.PublicKey, expected length %d`, ed25519.PublicKeySize)
		}
	}
	return nil
}

// SignEdDSA generates an EdDSA (Ed25519) signature for the given payload.
// The raw parameter should be the pre-computed signing input (typically header.payload).
// EdDSA is deterministic and doesn't require additional hashing of the input.
//
// This function is now a thin wrapper around dsig.SignEdDSA. For new projects, you should
// consider using dsig instead of this function.
//
// As a low-level primitive it assumes a well-formed, correctly-sized key; a
// wrong-length key may panic. Use jws.Sign for untrusted or unvalidated keys.
func SignEdDSA(key ed25519.PrivateKey, payload []byte) ([]byte, error) {
	// Use dsig.Sign with EdDSA algorithm constant
	return dsig.Sign(key, dsig.EdDSA, payload, nil)
}

// VerifyEdDSA verifies an EdDSA (Ed25519) signature for the given payload.
// This function verifies the signature using Ed25519 verification algorithm.
// The payload parameter should be the pre-computed signing input (typically header.payload).
// EdDSA is deterministic and provides strong security guarantees without requiring hash function selection.
//
// This function is now a thin wrapper around dsig.VerifyEdDSA. For new projects, you should
// consider using dsig instead of this function.
//
// As a low-level primitive it assumes a well-formed, correctly-sized key; a
// wrong-length key may panic. Use jws.Verify for untrusted or unvalidated keys.
func VerifyEdDSA(key ed25519.PublicKey, payload, signature []byte) error {
	// Use dsig.Verify with EdDSA algorithm constant
	return dsig.Verify(key, dsig.EdDSA, payload, signature)
}
