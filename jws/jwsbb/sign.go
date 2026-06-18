package jwsbb

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"io"

	"github.com/lestrrat-go/dsig"
	"github.com/lestrrat-go/jwx/v4/internal/keyconv"
)

// Sign generates a JWS signature using the specified key and algorithm.
//
// This function loads the signer registered in the jwsbb package _ONLY_.
// It does not support custom signers that the user might have registered.
//
// rr is an io.Reader that provides randomness for signing. If rr is nil, it defaults to rand.Reader.
// Not all algorithms require this parameter, but it is included for consistency.
// 99% of the time, you can pass nil for rr, and it will work fine.
//
// Deprecated in spirit: in the next major release of jwx (v5), the
// signature of Sign will change to match [SignWithOpts], i.e. it will
// accept an additional [crypto.SignerOpts] parameter immediately before
// rr. Callers that need to pass per-call options today should use
// [SignWithOpts]; callers that do not can keep using Sign and migrate
// when v5 ships by threading a nil opts argument through at the call
// site.
func Sign(key any, alg string, payload []byte, rr io.Reader) ([]byte, error) {
	return SignWithOpts(key, alg, payload, nil, rr)
}

// SignWithOpts is like [Sign] but threads an optional
// [crypto.SignerOpts] through to the underlying dsig signer. The
// canonical use case is composite ML-DSA signatures, where a per-call
// domain-separation context (`*mldsa.Options`) must reach
// `filippo.io/mldsa` via the `dsig.SignerWithOpts` interface
// implemented by `github.com/jwx-go/mldsa/v4`. For built-in families
// (HMAC, RSA, ECDSA, EdDSA) the opts argument is ignored.
//
// This function exists as a transitional API. In the next major release
// of jwx (v5) it will be removed and its signature will become the
// canonical shape of [Sign]. Code that uses SignWithOpts today will
// need a mechanical rename to Sign (and nothing else) when v5 ships.
func SignWithOpts(key any, alg string, payload []byte, opts crypto.SignerOpts, rr io.Reader) ([]byte, error) {
	dsigAlg, ok := GetDsigAlgorithm(alg)
	if !ok {
		// For custom algorithms registered with dsig, JWS name = dsig name
		dsigAlg = alg
	}

	// Get dsig algorithm info to determine key conversion strategy
	dsigInfo, ok := dsig.GetAlgorithmInfo(dsigAlg)
	if !ok {
		return nil, fmt.Errorf(`jwsbb.SignWithOpts: dsig algorithm %q not registered`, dsigAlg)
	}

	switch dsigInfo.Family {
	case dsig.HMAC:
		return dispatchHMACSign(key, dsigAlg, payload)
	case dsig.RSA:
		return dispatchRSASign(key, dsigAlg, payload, rr)
	case dsig.ECDSA:
		return dispatchECDSASign(key, dsigAlg, payload, rr)
	case dsig.EdDSAFamily:
		return dispatchEdDSASign(key, alg, dsigAlg, payload, rr)
	case dsig.Custom:
		return dsig.SignWithOpts(key, dsigAlg, payload, opts, rr)
	default:
		return nil, fmt.Errorf(`jwsbb.SignWithOpts: unsupported dsig algorithm family %q`, dsigInfo.Family)
	}
}

func dispatchHMACSign(key any, dsigAlg string, payload []byte) ([]byte, error) {
	hmackey, err := keyconv.KeyAs[[]byte](key)
	if err != nil {
		return nil, fmt.Errorf(`jwsbb.Sign: invalid key type %T. []byte is required: %w`, key, err)
	}

	return dsig.Sign(hmackey, dsigAlg, payload, nil)
}

func dispatchRSASign(key any, dsigAlg string, payload []byte, rr io.Reader) ([]byte, error) {
	// A malformed ed25519 key (value or pointer) satisfies crypto.Signer but
	// panics in Public(). Reject it before the crypto.Signer probe below, which
	// a cross-family caller (ed25519 key + RSA alg) could otherwise reach.
	if err := validateEd25519KeyShape(key); err != nil {
		return nil, fmt.Errorf(`jwsbb.Sign: %w`, err)
	}

	// Try crypto.Signer first (dsig can handle it directly)
	if signer, ok := key.(crypto.Signer); ok {
		// Verify it's an RSA key
		if _, ok := signer.Public().(*rsa.PublicKey); ok {
			return dsig.Sign(signer, dsigAlg, payload, rr)
		}
	}

	// Fall back to concrete key types
	privkey, err := keyconv.KeyAs[*rsa.PrivateKey](key)
	if err != nil {
		return nil, fmt.Errorf(`jwsbb.Sign: invalid key type %T. *rsa.PrivateKey is required: %w`, key, err)
	}

	return dsig.Sign(privkey, dsigAlg, payload, rr)
}

func dispatchECDSASign(key any, dsigAlg string, payload []byte, rr io.Reader) ([]byte, error) {
	// See dispatchRSASign: reject malformed ed25519 keys before the
	// crypto.Signer probe to avoid a cross-family Public() panic.
	if err := validateEd25519KeyShape(key); err != nil {
		return nil, fmt.Errorf(`jwsbb.Sign: %w`, err)
	}

	// Try crypto.Signer first (dsig can handle it directly)
	if signer, ok := key.(crypto.Signer); ok {
		// Verify it's an ECDSA key
		if _, ok := signer.Public().(*ecdsa.PublicKey); ok {
			return dsig.Sign(signer, dsigAlg, payload, rr)
		}
	}

	// Fall back to concrete key types
	privkey, err := keyconv.KeyAs[*ecdsa.PrivateKey](key)
	if err != nil {
		return nil, fmt.Errorf(`jwsbb.Sign: invalid key type %T. *ecdsa.PrivateKey is required: %w`, key, err)
	}

	return dsig.Sign(privkey, dsigAlg, payload, rr)
}

func dispatchEdDSASign(key any, jwsAlg, dsigAlg string, payload []byte, rr io.Reader) ([]byte, error) {
	// Note: Extension algorithms (e.g. Ed448) are registered as dsig.Custom family,
	// so they take the dsig.Custom branch in Sign() and never reach this function.

	// A concrete ed25519.PrivateKey satisfies crypto.Signer, but its Public()
	// method panics ("slice bounds out of range") when the key is not exactly
	// ed25519.PrivateKeySize bytes. Reject malformed keys here so we return an
	// error instead of panicking inside the crypto.Signer branch below.
	if err := validateEd25519KeyShape(key); err != nil {
		return nil, fmt.Errorf(`jwsbb.Sign: %w`, err)
	}

	// Try crypto.Signer first (dsig can handle it directly)
	if signer, ok := key.(crypto.Signer); ok {
		// Verify it's an EdDSA key
		if pub, ok := signer.Public().(ed25519.PublicKey); ok {
			// A custom signer may hand back a wrong-length ed25519.PublicKey,
			// which would panic inside dsig. Reject it before any crypto call.
			if err := validateEd25519KeyShape(pub); err != nil {
				return nil, fmt.Errorf(`jwsbb.Sign: %w`, err)
			}
			if err := validateEdDSACurve(jwsAlg, pub); err != nil {
				return nil, fmt.Errorf(`jwsbb.Sign: %w`, err)
			}
			return dsig.Sign(signer, dsigAlg, payload, rr)
		}
	}

	// Fall back to concrete key types
	privkeyPtr, err := keyconv.Ed25519PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf(`jwsbb.Sign: invalid key type %T. ed25519.PrivateKey is required: %w`, key, err)
	}
	privkey := *privkeyPtr

	if err := validateEdDSACurve(jwsAlg, privkey.Public()); err != nil {
		return nil, fmt.Errorf(`jwsbb.Sign: %w`, err)
	}

	return dsig.Sign(privkey, dsigAlg, payload, rr)
}
