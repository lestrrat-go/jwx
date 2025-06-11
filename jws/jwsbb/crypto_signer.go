package jwsbb

import (
	"crypto"
	"crypto/rand"
	"fmt"
)

func cryptosign(payload []byte, hash crypto.Hash, signer crypto.Signer, opts crypto.SignerOpts) ([]byte, error) {
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

func (s CryptoSigner) Sign(payload []byte, key crypto.Signer) ([]byte, error) {
	return cryptosign(payload, s.h, key, s.options)
}

func SignCryptoSigner(payload, protected []byte, h crypto.Hash, signer crypto.Signer, opts crypto.SignerOpts, encoder Base64Encoder, encodePayload bool) ([]byte, error) {
	return sign[crypto.Signer](payload, protected, CryptoSigner{h: h, options: opts}, encoder, encodePayload, signer)
}
