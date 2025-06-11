package jwsbb

import (
	"crypto"
	"crypto/rsa"
)

type RsaSigner struct {
	h   crypto.Hash
	pss bool
}

func RSAPSSOptions(h crypto.Hash) rsa.PSSOptions {
	return rsa.PSSOptions{
		Hash:       h,
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	}
}

func (s RsaSigner) Sign(payload []byte, key *rsa.PrivateKey) ([]byte, error) {
	var opts crypto.SignerOpts = s.h
	if s.pss {
		rsaopts := RSAPSSOptions(s.h)
		opts = &rsaopts
	}
	return cryptosign(payload, s.h, key, opts)
}

func SignRSA(payload, hdr []byte, h crypto.Hash, pss bool, encoder Base64Encoder, encodePayload bool, key *rsa.PrivateKey) ([]byte, error) {
	return sign[*rsa.PrivateKey](payload, hdr, RsaSigner{h: h, pss: pss}, encoder, encodePayload, key)
}

// RsaVerifier verifies RSA signatures using the specified hash and options.
type RsaVerifier struct {
	h   crypto.Hash
	pss bool
}

func (v RsaVerifier) Verify(buf []byte, signature []byte, key *rsa.PublicKey) error {
	hasher := v.h.New()
	hasher.Write(buf)
	digest := hasher.Sum(nil)
	if v.pss {
		return rsa.VerifyPSS(key, v.h, digest, signature, &rsa.PSSOptions{Hash: v.h, SaltLength: rsa.PSSSaltLengthEqualsHash})
	}
	return rsa.VerifyPKCS1v15(key, v.h, digest, signature)
}

// VerifyRSA verifies the RSA signature for the given payload and header.
func VerifyRSA(payload, hdr, signature []byte, h crypto.Hash, pss bool, encoder Base64Encoder, encodePayload bool, pubKey *rsa.PublicKey) error {
	return verify[*rsa.PublicKey](payload, hdr, signature, RsaVerifier{h: h, pss: pss}, encoder, encodePayload, pubKey)
}
