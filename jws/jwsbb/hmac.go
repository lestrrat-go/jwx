package jwsbb

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"github.com/lestrrat-go/jwx/v3/internal/base64"
)

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

type HMACSigner struct {
	hfunc func() hash.Hash
}

func NewHMACSigner(hfunc func() hash.Hash) HMACSigner {
	return HMACSigner{
		hfunc: hfunc,
	}
}

func (s HMACSigner) Sign(key, payload []byte) ([]byte, error) {
	h := hmac.New(s.hfunc, key)
	if _, err := h.Write(payload); err != nil {
		return nil, fmt.Errorf(`failed to write payload using hmac: %w`, err)
	}
	return h.Sum(nil), nil
}

// SignHMAC generates a single signature for the given payload
// using the specified hash function and key.
func SignHMAC(key, raw []byte, hfunc func() hash.Hash) ([]byte, error) {
	s := NewHMACSigner(hfunc)
	return s.Sign(key, raw)
}

type HMACVerifier struct {
	hfunc func() hash.Hash
}

func (v HMACVerifier) Verify(key, buf, signature []byte) error {
	expected := hmac.New(v.hfunc, key)
	expected.Write(buf)
	if !hmac.Equal(signature, expected.Sum(nil)) {
		return fmt.Errorf("invalid HMAC signature")
	}
	return nil
}

// VerifyHMAC verifies the HMAC signature for the given payload and header.
func VerifyHMAC(key, payload, hdr, signature []byte, hfunc func() hash.Hash, encoder base64.Encoder, encodePayload bool) error {
	return Verify[[]byte](key, payload, hdr, signature, HMACVerifier{hfunc: hfunc}, encoder, encodePayload)
}
