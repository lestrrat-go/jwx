package jwsbb

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"

	"github.com/lestrrat-go/dsig"
)

var rsaHashFuncs = map[string]struct {
	Hash crypto.Hash
	PSS  bool // whether to use PSS padding
}{
	rs256: {Hash: crypto.SHA256, PSS: false},
	rs384: {Hash: crypto.SHA384, PSS: false},
	rs512: {Hash: crypto.SHA512, PSS: false},
	ps256: {Hash: crypto.SHA256, PSS: true},
	ps384: {Hash: crypto.SHA384, PSS: true},
	ps512: {Hash: crypto.SHA512, PSS: true},
}

// RSAHashFuncFor returns the appropriate hash function and PSS flag for the given RSA algorithm.
// Supported algorithms: RS256, RS384, RS512 (PKCS#1 v1.5) and PS256, PS384, PS512 (PSS).
// Returns the hash function, PSS flag, and an error if the algorithm is unsupported.
func RSAHashFuncFor(alg string) (crypto.Hash, bool, error) {
	if h, ok := rsaHashFuncs[alg]; ok {
		return h.Hash, h.PSS, nil
	}
	return 0, false, fmt.Errorf("unsupported RSA algorithm %s", alg)
}

// RSAPSSOptions returns the PSS options for RSA-PSS signatures with the specified hash.
// The salt length is set to equal the hash length as per RFC 7518.
func RSAPSSOptions(h crypto.Hash) rsa.PSSOptions {
	return rsa.PSSOptions{
		Hash:       h,
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	}
}

// rsaAlgorithmForHash returns the appropriate dsig algorithm string for the given hash and PSS flag.
func rsaAlgorithmForHash(h crypto.Hash, pss bool) (string, error) {
	if pss {
		switch h {
		case crypto.SHA256:
			return dsig.RSAPSSWithSHA256, nil
		case crypto.SHA384:
			return dsig.RSAPSSWithSHA384, nil
		case crypto.SHA512:
			return dsig.RSAPSSWithSHA512, nil
		default:
			return "", fmt.Errorf("unsupported hash function for RSA-PSS: %v", h)
		}
	} else {
		switch h {
		case crypto.SHA256:
			return dsig.RSAPKCS1v15WithSHA256, nil
		case crypto.SHA384:
			return dsig.RSAPKCS1v15WithSHA384, nil
		case crypto.SHA512:
			return dsig.RSAPKCS1v15WithSHA512, nil
		default:
			return "", fmt.Errorf("unsupported hash function for RSA PKCS#1 v1.5: %v", h)
		}
	}
}

// SignRSA generates an RSA signature for the given payload using the specified private key and options.
// The raw parameter should be the pre-computed signing input (typically header.payload).
// If pss is true, RSA-PSS is used; otherwise, PKCS#1 v1.5 is used.
//
// The rr parameter is an optional io.Reader that can be used to provide randomness for signing.
// If rr is nil, it defaults to rand.Reader.
func SignRSA(key *rsa.PrivateKey, payload []byte, h crypto.Hash, pss bool, rr io.Reader) ([]byte, error) {
	alg, err := rsaAlgorithmForHash(h, pss)
	if err != nil {
		return nil, err
	}

	// Use dsig.Sign
	return dsig.Sign(key, alg, payload, rr)
}

// VerifyRSA verifies an RSA signature for the given payload and header.
// This function constructs the signing input by encoding the header and payload according to JWS specification,
// then verifies the signature using the specified public key and hash algorithm.
// If pss is true, RSA-PSS verification is used; otherwise, PKCS#1 v1.5 verification is used.
func VerifyRSA(key *rsa.PublicKey, payload, signature []byte, h crypto.Hash, pss bool) error {
	alg, err := rsaAlgorithmForHash(h, pss)
	if err != nil {
		return err
	}

	// Use dsig.Verify
	return dsig.Verify(key, alg, payload, signature)
}
