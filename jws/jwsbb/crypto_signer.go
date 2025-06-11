package jwsbb

import (
	"crypto"
	"crypto/rand"
	"fmt"
)

func cryptosign(payload []byte, hash crypto.Hash, signer crypto.Signer, opts crypto.SignerOpts) ([]byte, error) {
	h := hash.New()
	if _, err := h.Write(payload); err != nil {
		return nil, fmt.Errorf(`failed to write payload to hash: %w`, err)
	}
	return signer.Sign(rand.Reader, h.Sum(nil), opts)
}
