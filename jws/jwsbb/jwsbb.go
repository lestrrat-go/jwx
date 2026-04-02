// Package jwsbb provides the building blocks (hence the name "bb") for JWS operations.
// It should be thought of as a low-level API, almost akin to internal packages
// that should not be used directly by users of the jwx package. However, these exist
// to provide a more efficient way to perform JWS operations without the overhead of
// the higher-level jws package to power-users who know what they are doing.
//
// This package is currently considered EXPERIMENTAL, and the API may change
// without notice. It is not recommended to use this package unless you are
// fully aware of the implications of using it.
//
// All bb packages in jwx follow the same design principles:
// 1. Does minimal checking of input parameters (for performance); callers need to ensure that the parameters are valid.
// 2. All exported functions are strongly typed (i.e. they do not take `any` types unless they absolutely have to).
// 3. Does not rely on other public jwx packages (they are standalone, except for internal packages).
//
// This implementation uses github.com/lestrrat-go/dsig as the underlying signature provider.
package jwsbb

import (
	"crypto"
	"crypto/ed25519"
	"fmt"

	"github.com/lestrrat-go/dsig"
)

// JWS algorithm name constants
const (
	// HMAC algorithms
	hs256 = "HS256"
	hs384 = "HS384"
	hs512 = "HS512"

	// RSA PKCS#1 v1.5 algorithms
	rs256 = "RS256"
	rs384 = "RS384"
	rs512 = "RS512"

	// RSA PSS algorithms
	ps256 = "PS256"
	ps384 = "PS384"
	ps512 = "PS512"

	// ECDSA algorithms
	es256 = "ES256"
	es384 = "ES384"
	es512 = "ES512"

	// EdDSA algorithm
	edDSA = "EdDSA"

	// Fully-specified EdDSA algorithms (RFC 9864)
	edDSAEd25519 = "Ed25519"
)

// Signer is a generic interface that defines the method for signing payloads.
// The type parameter K represents the key type (e.g., []byte for HMAC keys,
// *rsa.PrivateKey for RSA keys, *ecdsa.PrivateKey for ECDSA keys).
type Signer[K any] interface {
	Sign(key K, payload []byte) ([]byte, error)
}

// Verifier is a generic interface that defines the method for verifying signatures.
// The type parameter K represents the key type (e.g., []byte for HMAC keys,
// *rsa.PublicKey for RSA keys, *ecdsa.PublicKey for ECDSA keys).
type Verifier[K any] interface {
	Verify(key K, buf []byte, signature []byte) error
}

// JWS to dsig algorithm mapping
var jwsToDsigAlgorithm = map[string]string{
	// HMAC algorithms
	hs256: dsig.HMACWithSHA256,
	hs384: dsig.HMACWithSHA384,
	hs512: dsig.HMACWithSHA512,

	// RSA PKCS#1 v1.5 algorithms
	rs256: dsig.RSAPKCS1v15WithSHA256,
	rs384: dsig.RSAPKCS1v15WithSHA384,
	rs512: dsig.RSAPKCS1v15WithSHA512,

	// RSA PSS algorithms
	ps256: dsig.RSAPSSWithSHA256,
	ps384: dsig.RSAPSSWithSHA384,
	ps512: dsig.RSAPSSWithSHA512,

	// ECDSA algorithms
	es256: dsig.ECDSAWithP256AndSHA256,
	es384: dsig.ECDSAWithP384AndSHA384,
	es512: dsig.ECDSAWithP521AndSHA512,
	// Note: ES256K requires external dependency and is handled separately

	// EdDSA algorithm
	edDSA: dsig.EdDSA,

	// Fully-specified EdDSA algorithms (RFC 9864)
	edDSAEd25519: dsig.EdDSA,
}

// getDsigAlgorithm returns the dsig algorithm name for a JWS algorithm
func getDsigAlgorithm(jwsAlg string) (string, bool) {
	dsigAlg, ok := jwsToDsigAlgorithm[jwsAlg]
	return dsigAlg, ok
}

// Extension algorithm registries for algorithms not handled by dsig
// (e.g. Ed448 from a separate module). Populated via RegisterAlgorithm.
var extSigners = map[string]Signer[any]{}
var extVerifiers = map[string]Verifier[any]{}

// RegisterAlgorithm registers a signer and/or verifier for an extension
// algorithm not handled by the built-in dsig mapping. This is intended
// to be called from init() in external modules that provide the crypto
// implementation (e.g. Ed448).
//
// At least one of signer or verifier must be non-nil. Pass nil for the
// other when only one direction is needed (e.g. verify-only).
//
// Returns an error if:
//   - alg is empty
//   - alg collides with a built-in algorithm
//   - alg is already registered (call UnregisterAlgorithm first to replace)
//   - both signer and verifier are nil
//
// This function is NOT concurrency-safe. It must be called during init()
// or before any Sign/Verify calls.
func RegisterAlgorithm(alg string, signer Signer[any], verifier Verifier[any]) error {
	if alg == "" {
		return fmt.Errorf(`jwsbb.RegisterAlgorithm: algorithm name must not be empty`)
	}
	if _, ok := jwsToDsigAlgorithm[alg]; ok {
		return fmt.Errorf(`jwsbb.RegisterAlgorithm: algorithm %q is a built-in algorithm and cannot be overridden`, alg)
	}
	if _, ok := extSigners[alg]; ok {
		return fmt.Errorf(`jwsbb.RegisterAlgorithm: algorithm %q is already registered`, alg)
	}
	if _, ok := extVerifiers[alg]; ok {
		return fmt.Errorf(`jwsbb.RegisterAlgorithm: algorithm %q is already registered`, alg)
	}
	if signer == nil && verifier == nil {
		return fmt.Errorf(`jwsbb.RegisterAlgorithm: at least one of signer or verifier must be non-nil`)
	}

	if signer != nil {
		extSigners[alg] = signer
	}
	if verifier != nil {
		extVerifiers[alg] = verifier
	}
	return nil
}

// UnregisterAlgorithm removes a previously registered extension algorithm.
// It is a no-op if the algorithm was not registered.
//
// This function is NOT concurrency-safe. It must be called during init()
// or before any Sign/Verify calls.
func UnregisterAlgorithm(alg string) {
	delete(extSigners, alg)
	delete(extVerifiers, alg)
}

// validateEdDSACurve enforces that fully-specified EdDSA algorithms (RFC 9864)
// are only used with the correct key curve. The polymorphic "EdDSA" algorithm
// accepts any EdDSA key without curve checks. The pub argument must be the
// already-extracted public key (after jwk.Key unwrapping / keyconv).
func validateEdDSACurve(jwsAlg string, pub crypto.PublicKey) error {
	switch jwsAlg {
	case edDSAEd25519:
		if _, ok := pub.(ed25519.PublicKey); !ok {
			return fmt.Errorf(`algorithm %q requires an Ed25519 key, got %T`, jwsAlg, pub)
		}
	case edDSA:
		// Polymorphic EdDSA: no curve restriction
	default:
		return fmt.Errorf(`unsupported fully-specified EdDSA algorithm %q`, jwsAlg)
	}
	return nil
}
