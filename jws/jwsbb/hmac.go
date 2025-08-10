package jwsbb

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"github.com/lestrrat-go/dsig"
)

var hmacHashFuncs = map[string]func() hash.Hash{
	hs256: sha256.New,
	hs384: sha512.New384,
	hs512: sha512.New,
}

// HMACHashFuncFor returns the appropriate hash function for the given HMAC algorithm.
// Supported algorithms: HS256 (SHA-256), HS384 (SHA-384), HS512 (SHA-512).
// Returns the hash function constructor and an error if the algorithm is unsupported.
func HMACHashFuncFor(alg string) (func() hash.Hash, error) {
	if h, ok := hmacHashFuncs[alg]; ok {
		return h, nil
	}
	return nil, fmt.Errorf("unsupported HMAC algorithm %s", alg)
}

// hmacAlgorithmForHashFunc returns the appropriate dsig algorithm string for the given hash function.
func hmacAlgorithmForHashFunc(hfunc func() hash.Hash) (string, error) {
	h := hfunc()
	switch h.Size() {
	case 32: // SHA-256
		return dsig.HMACWithSHA256, nil
	case 48: // SHA-384
		return dsig.HMACWithSHA384, nil
	case 64: // SHA-512
		return dsig.HMACWithSHA512, nil
	default:
		return "", fmt.Errorf("unsupported HMAC hash function")
	}
}

// SignHMAC generates an HMAC signature for the given payload using the specified hash function and key.
// The raw parameter should be the pre-computed signing input (typically header.payload).
func SignHMAC(key, payload []byte, hfunc func() hash.Hash) ([]byte, error) {
	alg, err := hmacAlgorithmForHashFunc(hfunc)
	if err != nil {
		return nil, err
	}

	// Use dsig.Sign
	return dsig.Sign(key, alg, payload, nil)
}

// VerifyHMAC verifies an HMAC signature for the given payload.
// This function verifies the signature using the specified key and hash function.
// The payload parameter should be the pre-computed signing input (typically header.payload).
func VerifyHMAC(key, payload, signature []byte, hfunc func() hash.Hash) error {
	alg, err := hmacAlgorithmForHashFunc(hfunc)
	if err != nil {
		return err
	}

	// Use dsig.Verify
	return dsig.Verify(key, alg, payload, signature)
}
