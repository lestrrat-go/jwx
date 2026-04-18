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
	"sync"

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

// dsigAlgorithmDB maps JWS algorithm names to dsig algorithm names.
// Uses sync.Map for lock-free reads of stable entries (registered at init time).
var dsigAlgorithmDB sync.Map // map[string]string

func init() {
	// Register built-in JWS-to-dsig algorithm mappings
	for jwsAlg, dsigAlg := range map[string]string{
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
	} {
		dsigAlgorithmDB.Store(jwsAlg, dsigAlg)
	}
}

// RegisterDsigAlgorithm registers a mapping from a JWS algorithm name
// to a dsig algorithm name. This allows extension modules to add support
// for new algorithms that use the default signer/verifier dispatch.
//
// The error return is reserved for future validation. The current
// implementation always returns nil, but callers — especially extension
// modules calling this from init() — must check the return value and panic
// on failure to stay forward-compatible.
func RegisterDsigAlgorithm(jwsAlg, dsigAlg string) error {
	dsigAlgorithmDB.Store(jwsAlg, dsigAlg)
	return nil
}

// GetDsigAlgorithm returns the dsig algorithm name registered for the given
// JWS algorithm name. It returns ok=false if the algorithm has not been
// registered; extension modules register new mappings with
// [RegisterDsigAlgorithm] at init time.
func GetDsigAlgorithm(jwsAlg string) (string, bool) {
	v, ok := dsigAlgorithmDB.Load(jwsAlg)
	if !ok {
		return "", false
	}
	//nolint:forcetypeassert
	return v.(string), true // always stored as string
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
