package jwsbb

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"

	"github.com/lestrrat-go/dsig"
	"github.com/lestrrat-go/jwx/v4/internal/keyconv"
)

// Verify verifies a JWS signature using the specified key and algorithm.
//
// This function loads the verifier registered in the jwsbb package _ONLY_.
// It does not support custom verifiers that the user might have registered.
//
// Deprecated in spirit: in the next major release of jwx (v5), the
// signature of Verify will change to match [VerifyWithOpts], i.e. it
// will accept an additional [crypto.SignerOpts] parameter at the end.
// Callers that need to pass per-call options today should use
// [VerifyWithOpts]; callers that do not can keep using Verify and
// migrate when v5 ships by threading a nil opts argument through at
// the call site.
func Verify(key any, alg string, payload, signature []byte) error {
	return VerifyWithOpts(key, alg, payload, signature, nil)
}

// VerifyWithOpts is like [Verify] but threads an optional
// [crypto.SignerOpts] through to the underlying dsig verifier. See
// [SignWithOpts] for the rationale and the migration story.
func VerifyWithOpts(key any, alg string, payload, signature []byte, opts crypto.SignerOpts) error {
	dsigAlg, ok := GetDsigAlgorithm(alg)
	if !ok {
		// For custom algorithms registered with dsig, JWS name = dsig name
		dsigAlg = alg
	}

	// Get dsig algorithm info to determine key conversion strategy
	dsigInfo, ok := dsig.GetAlgorithmInfo(dsigAlg)
	if !ok {
		return fmt.Errorf(`jwsbb.VerifyWithOpts: dsig algorithm %q not registered`, dsigAlg)
	}

	switch dsigInfo.Family {
	case dsig.HMAC:
		return dispatchHMACVerify(key, dsigAlg, payload, signature)
	case dsig.RSA:
		return dispatchRSAVerify(key, dsigAlg, payload, signature)
	case dsig.ECDSA:
		return dispatchECDSAVerify(key, dsigAlg, payload, signature)
	case dsig.EdDSAFamily:
		return dispatchEdDSAVerify(key, alg, dsigAlg, payload, signature)
	case dsig.Custom:
		return dsig.VerifyWithOpts(key, dsigAlg, payload, signature, opts)
	default:
		return fmt.Errorf(`jwsbb.VerifyWithOpts: unsupported dsig algorithm family %q`, dsigInfo.Family)
	}
}

func dispatchHMACVerify(key any, dsigAlg string, payload, signature []byte) error {
	hmackey, err := keyconv.KeyAs[[]byte](key)
	if err != nil {
		return fmt.Errorf(`jwsbb.Verify: invalid key type %T. []byte is required: %w`, key, err)
	}

	return dsig.Verify(hmackey, dsigAlg, payload, signature)
}

func dispatchRSAVerify(key any, dsigAlg string, payload, signature []byte) error {
	// A malformed ed25519 key (value or pointer) satisfies crypto.Signer but
	// panics in Public(). Reject it before the crypto.Signer probe below, which
	// a cross-family caller (ed25519 key + RSA alg) could otherwise reach.
	if err := validateEd25519KeyShape(key); err != nil {
		return fmt.Errorf(`jwsbb.Verify: %w`, err)
	}

	// Try crypto.Signer first (dsig can handle it directly)
	if signer, ok := key.(crypto.Signer); ok {
		// Verify it's an RSA key
		if _, ok := signer.Public().(*rsa.PublicKey); ok {
			return dsig.Verify(signer, dsigAlg, payload, signature)
		}
	}

	// Fall back to concrete key types
	pubkey, err := keyconv.RSAPublicKey(key)
	if err != nil {
		return fmt.Errorf(`jwsbb.Verify: invalid key type %T. *rsa.PublicKey is required: %w`, key, err)
	}

	return dsig.Verify(pubkey, dsigAlg, payload, signature)
}

func dispatchECDSAVerify(key any, dsigAlg string, payload, signature []byte) error {
	// See dispatchRSAVerify: reject malformed ed25519 keys before the
	// crypto.Signer probe to avoid a cross-family Public() panic.
	if err := validateEd25519KeyShape(key); err != nil {
		return fmt.Errorf(`jwsbb.Verify: %w`, err)
	}

	// Try crypto.Signer first (dsig can handle it directly)
	if signer, ok := key.(crypto.Signer); ok {
		// Verify it's an ECDSA key
		if _, ok := signer.Public().(*ecdsa.PublicKey); ok {
			return dsig.Verify(signer, dsigAlg, payload, signature)
		}
	}

	// Fall back to concrete key types
	pubkey, err := keyconv.ECDSAPublicKey(key)
	if err != nil {
		return fmt.Errorf(`jwsbb.Verify: invalid key type %T. *ecdsa.PublicKey is required: %w`, key, err)
	}

	return dsig.Verify(pubkey, dsigAlg, payload, signature)
}

func dispatchEdDSAVerify(key any, jwsAlg, dsigAlg string, payload, signature []byte) error {
	// Note: Extension algorithms (e.g. Ed448) are registered as dsig.Custom family,
	// so they take the dsig.Custom branch in Verify() and never reach this function.

	// A concrete ed25519.PrivateKey satisfies crypto.Signer, but its Public()
	// method panics ("slice bounds out of range") when the key is not exactly
	// ed25519.PrivateKeySize bytes. Reject malformed keys here so we return an
	// error instead of panicking inside the crypto.Signer branch below.
	if err := validateEd25519KeyShape(key); err != nil {
		return fmt.Errorf(`jwsbb.Verify: %w`, err)
	}

	// Try crypto.Signer first (dsig can handle it directly)
	if signer, ok := key.(crypto.Signer); ok {
		// Verify it's an EdDSA key
		if pub, ok := signer.Public().(ed25519.PublicKey); ok {
			// A custom signer may hand back a wrong-length ed25519.PublicKey,
			// which would panic inside dsig. Reject it before any crypto call.
			if err := validateEd25519KeyShape(pub); err != nil {
				return fmt.Errorf(`jwsbb.Verify: %w`, err)
			}
			if err := validateEdDSACurve(jwsAlg, pub); err != nil {
				return fmt.Errorf(`jwsbb.Verify: %w`, err)
			}
			return dsig.Verify(signer, dsigAlg, payload, signature)
		}
	}

	// Fall back to concrete key types
	pubkeyPtr, err := keyconv.Ed25519PublicKey(key)
	if err != nil {
		return fmt.Errorf(`jwsbb.Verify: invalid key type %T. ed25519.PublicKey is required: %w`, key, err)
	}
	pubkey := *pubkeyPtr

	if err := validateEdDSACurve(jwsAlg, pubkey); err != nil {
		return fmt.Errorf(`jwsbb.Verify: %w`, err)
	}

	return dsig.Verify(pubkey, dsigAlg, payload, signature)
}
