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
	"crypto/sha256"
	"crypto/sha512"
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
	es256  = "ES256"
	es256k = "ES256K"
	es384  = "ES384"
	es512  = "ES512"

	// EdDSA algorithm
	edDSA = "EdDSA"
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

type Family int

const (
	InvalidFamily Family = iota
	HMAC
	RSA
	ECDSA
	EdDSA
	maxFamily
)

type AlgorithmInfo struct {
	Family Family
	Dsig   string
	Meta   any
}

var algorithms = make(map[string]AlgorithmInfo)
var muAlgorithms sync.RWMutex

// RegisterAlgorithm registers a new JWS algorithm with the specified family and dsig algorithm.
//
// `info.Meta` should contain extra metadata for some algorithms. Currently HMAC, RSA,
// and ECDSA family of algorithms need their respective metadata (HMACFamilyMeta,
// RSAFamilyMeta, and ECDSAFamilyMeta). Metadata for other families are ignored.
func RegisterAlgorithm(alg string, info AlgorithmInfo) error {
	muAlgorithms.Lock()
	defer muAlgorithms.Unlock()

	// We need to register reverse lookup maps for SignXXXX/VerifyXXX
	// Note: Currently EdDSA does not have reverse lookup maps.
	switch info.Family {
	case HMAC:
		meta, ok := info.Meta.(HMACFamilyMeta)
		if !ok {
			return fmt.Errorf("invalid HMAC metadata for algorithm %s", alg)
		}
		muHMACReverseMap.Lock()
		hmacReverseMap[meta.Hash.Size()] = info.Dsig
		muHMACReverseMap.Unlock()
	case ECDSA:
		meta, ok := info.Meta.(ECDSAFamilyMeta)
		if !ok {
			return fmt.Errorf("invalid ECDSA metadata for algorithm %s", alg)
		}
		muECDSAReverseMap.Lock()
		ecdsaReverseMap[meta] = info.Dsig
		muECDSAReverseMap.Unlock()
	case RSA:
		meta, ok := info.Meta.(RSAFamilyMeta)
		if !ok {
			return fmt.Errorf("invalid RSA family metadata for algorithm %s", alg)
		}
		muRSAReverseMap.Lock()
		rsaReverseMap[meta] = info.Dsig
		muRSAReverseMap.Unlock()
	}

	algorithms[alg] = info
	return nil
}

func getAlgorithmInfo(alg string) (AlgorithmInfo, bool) {
	muAlgorithms.RLock()
	defer muAlgorithms.RUnlock()

	info, ok := algorithms[alg]
	return info, ok
}

func init() {
	toRegister := map[string]AlgorithmInfo{
		// HMAC algorithms
		hs256: {
			Family: HMAC,
			Dsig:   dsig.HMACWithSHA256,
			Meta: HMACFamilyMeta{
				Hash: sha256.New(),
			},
		},
		hs384: {
			Family: HMAC,
			Dsig:   dsig.HMACWithSHA384,
			Meta: HMACFamilyMeta{
				Hash: sha512.New384(),
			},
		},
		hs512: {
			Family: HMAC,
			Dsig:   dsig.HMACWithSHA512,
			Meta: HMACFamilyMeta{
				Hash: sha512.New(),
			},
		},

		// RSA PKCS#1 v1.5 algorithms
		rs256: {
			Family: RSA,
			Dsig:   dsig.RSAPKCS1v15WithSHA256,
			Meta: RSAFamilyMeta{
				Hash: crypto.SHA256,
				PSS:  false,
			},
		},
		rs384: {
			Family: RSA,
			Dsig:   dsig.RSAPKCS1v15WithSHA384,
			Meta: RSAFamilyMeta{
				Hash: crypto.SHA384,
				PSS:  false,
			},
		},
		rs512: {
			Family: RSA,
			Dsig:   dsig.RSAPKCS1v15WithSHA512,
			Meta: RSAFamilyMeta{
				Hash: crypto.SHA512,
				PSS:  false,
			},
		},

		// RSA PSS algorithms
		ps256: {
			Family: RSA,
			Dsig:   dsig.RSAPSSWithSHA256,
			Meta: RSAFamilyMeta{
				Hash: crypto.SHA256,
				PSS:  true,
			},
		},
		ps384: {
			Family: RSA,
			Dsig:   dsig.RSAPSSWithSHA384,
			Meta: RSAFamilyMeta{
				Hash: crypto.SHA384,
				PSS:  true,
			},
		},
		ps512: {
			Family: RSA,
			Dsig:   dsig.RSAPSSWithSHA512,
			Meta: RSAFamilyMeta{
				Hash: crypto.SHA512,
				PSS:  true,
			},
		},

		// ECDSA algorithms
		es256: {
			Family: ECDSA,
			Dsig:   dsig.ECDSAWithP256AndSHA256,
			Meta: ECDSAFamilyMeta{
				Hash: crypto.SHA256,
			},
		},
		es384: {
			Family: ECDSA,
			Dsig:   dsig.ECDSAWithP384AndSHA384,
			Meta: ECDSAFamilyMeta{
				Hash: crypto.SHA384,
			},
		},
		es512: {
			Family: ECDSA,
			Dsig:   dsig.ECDSAWithP521AndSHA512,
			Meta: ECDSAFamilyMeta{
				Hash: crypto.SHA512,
			},
		},

		// EdDSA algorithm
		edDSA: {
			Family: EdDSA,
			Dsig:   dsig.EdDSA,
		},
	}
	for alg, info := range toRegister {
		if err := RegisterAlgorithm(alg, info); err != nil {
			panic(fmt.Sprintf("failed to register algorithm %s: %v", alg, err))
		}
	}
}
