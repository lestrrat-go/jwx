package jwsbb

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"github.com/lestrrat-go/jwx/v3/internal/base64"
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

// hmacSigner implements HMAC signature generation using the specified hash function.
type hmacSigner struct {
	hfunc func() hash.Hash
}

// newHMACSigner creates a new HMAC signer with the specified hash function.
func newHMACSigner(hfunc func() hash.Hash) hmacSigner {
	return hmacSigner{
		hfunc: hfunc,
	}
}

func (s hmacSigner) Sign(key, payload []byte) ([]byte, error) {
	h := hmac.New(s.hfunc, key)
	if _, err := h.Write(payload); err != nil {
		return nil, fmt.Errorf(`failed to write payload using hmac: %w`, err)
	}
	return h.Sum(nil), nil
}

// SignHMAC generates an HMAC signature for the given payload using the specified hash function and key.
// The raw parameter should be the pre-computed signing input (typically header.payload).
func SignHMAC(key, raw []byte, hfunc func() hash.Hash) ([]byte, error) {
	s := newHMACSigner(hfunc)
	return s.Sign(key, raw)
}

// hmacVerifier implements HMAC signature verification using the specified hash function.
type hmacVerifier struct {
	hfunc func() hash.Hash
}

func (v hmacVerifier) Verify(key, buf, signature []byte) error {
	expected := hmac.New(v.hfunc, key)
	expected.Write(buf)
	if !hmac.Equal(signature, expected.Sum(nil)) {
		return fmt.Errorf("invalid HMAC signature")
	}
	return nil
}

// VerifyHMAC verifies an HMAC signature for the given payload and header.
// This function constructs the signing input by encoding the header and payload according to JWS specification,
// then verifies the signature using constant-time comparison to prevent timing attacks.
func VerifyHMAC(key, payload, hdr, signature []byte, hfunc func() hash.Hash, encoder base64.Encoder, encodePayload bool) error {
	return Verify[[]byte](key, payload, hdr, signature, hmacVerifier{hfunc: hfunc}, encoder, encodePayload)
}
