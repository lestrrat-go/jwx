package jwsbb

import (
	"crypto/hmac"
	"fmt"
	"hash"
)

type HmacSigner struct {
	hfunc func() hash.Hash
}

func (s HmacSigner) Sign(key, payload []byte) ([]byte, error) {
	h := hmac.New(s.hfunc, key)
	if _, err := h.Write(payload); err != nil {
		return nil, fmt.Errorf(`failed to write payload using hmac: %w`, err)
	}
	return h.Sum(nil), nil
}

// SignHMAC generates a single signature for the given payload using the
// specified hash function and key.
func SignHMAC(key, payload, hdr []byte, hfunc func() hash.Hash, encoder Base64Encoder, encodePayload bool) ([]byte, error) {
	return Sign[[]byte](key, payload, hdr, HmacSigner{hfunc: hfunc}, encoder, encodePayload)
}

type HmacVerifier struct {
	hfunc func() hash.Hash
}

func (v HmacVerifier) Verify(key, buf, signature []byte) error {
	expected := hmac.New(v.hfunc, key)
	expected.Write(buf)
	if !hmac.Equal(signature, expected.Sum(nil)) {
		return fmt.Errorf("invalid HMAC signature")
	}
	return nil
}

// VerifyHMAC verifies the HMAC signature for the given payload and header.
func VerifyHMAC(key, payload, hdr, signature []byte, hfunc func() hash.Hash, encoder Base64Encoder, encodePayload bool) error {
	return Verify[[]byte](key, payload, hdr, signature, HmacVerifier{hfunc: hfunc}, encoder, encodePayload)
}
