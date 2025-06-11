package jwsbb

import (
	"crypto"
	"crypto/rand"
	"fmt"
)

func cryptosign(signer crypto.Signer, payload []byte, hash crypto.Hash, opts crypto.SignerOpts) ([]byte, error) {
	var digest []byte
	if hash == crypto.Hash(0) {
		digest = payload
	} else {
		h := hash.New()
		if _, err := h.Write(payload); err != nil {
			return nil, fmt.Errorf(`failed to write payload to hash: %w`, err)
		}
		digest = h.Sum(nil)
	}
	return signer.Sign(rand.Reader, digest, opts)
}

type CryptoSigner struct {
	h       crypto.Hash
	options crypto.SignerOpts
}

func (s CryptoSigner) Sign(key crypto.Signer, payload []byte) ([]byte, error) {
	return cryptosign(key, payload, s.h, s.options)
}

func SignCryptoSigner(signer crypto.Signer, payload, protected []byte, h crypto.Hash, opts crypto.SignerOpts, encoder Base64Encoder, encodePayload bool) ([]byte, error) {
	return Sign[crypto.Signer](signer, payload, protected, CryptoSigner{h: h, options: opts}, encoder, encodePayload)
}
