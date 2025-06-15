package jwsbb

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"github.com/lestrrat-go/jwx/v3/internal/keyconv"
)

// HMACHashFuncFor returns the appropriate hash function for the given HMAC algorithm.
// Supported algorithms: HS256 (SHA-256), HS384 (SHA-384), HS512 (SHA-512).
// Returns the hash function constructor and an error if the algorithm is unsupported.
func HMACHashFuncFor(alg string) (func() hash.Hash, error) {
	switch alg {
	case "HS256":
		return sha256.New, nil
	case "HS384":
		return sha512.New384, nil
	case "HS512":
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("unsupported HMAC algorithm %s", alg)
	}
}

func toHMACKey(dst *[]byte, key any) error {
	if err := keyconv.ByteSliceKey(dst, key); err != nil {
		return fmt.Errorf(`jws.toHMACKey: invalid key type %T. []byte is required: %w`, key, err)
	}

	if len(*dst) == 0 {
		return fmt.Errorf(`jws.toHMACKey: missing key while signing payload`)
	}
	return nil
}

// SignHMAC generates an HMAC signature for the given payload using the specified hash function and key.
// The raw parameter should be the pre-computed signing input (typically header.payload).
func SignHMAC(key, payload []byte, hfunc func() hash.Hash) ([]byte, error) {
	h := hmac.New(hfunc, key)
	if _, err := h.Write(payload); err != nil {
		return nil, fmt.Errorf(`failed to write payload using hmac: %w`, err)
	}
	return h.Sum(nil), nil
}

// VerifyHMAC verifies an HMAC signature for the given payload.
// This function verifies the signature using the specified key and hash function.
// The payload parameter should be the pre-computed signing input (typically header.payload).
func VerifyHMAC(key, payload, signature []byte, hfunc func() hash.Hash) error {
	expected, err := SignHMAC(key, payload, hfunc)
	if err != nil {
		return fmt.Errorf("failed to sign payload for verification: %w", err)
	}
	if !hmac.Equal(signature, expected) {
		return fmt.Errorf("invalid HMAC signature")
	}
	return nil
}
