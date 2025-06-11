package jwsbb

import (
	"crypto/hmac"
	"fmt"
	"hash"
)

type HmacSigner struct {
	hfunc func() hash.Hash
}

func (s HmacSigner) Sign(payload []byte, key []byte) ([]byte, error) {
	h := hmac.New(s.hfunc, key)
	if _, err := h.Write(payload); err != nil {
		return nil, fmt.Errorf(`failed to write payload using hmac: %w`, err)
	}
	return h.Sum(nil), nil
}

// SignHMAC generates a single signature for the given payload using the
// specified hash function and key.
func SignHMAC(payload, hdr []byte, hfunc func() hash.Hash, encoder Base64Encoder, encodePayload bool, key []byte) ([]byte, error) {
	return sign[[]byte](payload, hdr, HmacSigner{hfunc: hfunc}, encoder, encodePayload, key)
}

type HmacVerifier struct {
	hfunc func() hash.Hash
}

func (v HmacVerifier) Verify(buf []byte, signature []byte, key []byte) error {
	expected := hmac.New(v.hfunc, key)
	expected.Write(buf)
	if !hmac.Equal(signature, expected.Sum(nil)) {
		return fmt.Errorf("invalid HMAC signature")
	}
	return nil
}

// VerifyHMAC verifies the HMAC signature for the given payload and header.
func VerifyHMAC(payload, hdr, signature []byte, hfunc func() hash.Hash, encoder Base64Encoder, encodePayload bool, key []byte) error {
	return verify[[]byte](payload, hdr, signature, HmacVerifier{hfunc: hfunc}, encoder, encodePayload, key)
}
