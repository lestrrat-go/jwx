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

func (s RsaSigner) Sign(key *rsa.PrivateKey, payload []byte) ([]byte, error) {
	var opts crypto.SignerOpts = s.h
	if s.pss {
		rsaopts := RSAPSSOptions(s.h)
		opts = &rsaopts
	}
	return cryptosign(key, payload, s.h, opts)
}

func SignRSA(key *rsa.PrivateKey, payload, hdr []byte, h crypto.Hash, pss bool, encoder Base64Encoder, encodePayload bool) ([]byte, error) {
	return Sign[*rsa.PrivateKey](key, payload, hdr, RsaSigner{h: h, pss: pss}, encoder, encodePayload)
}

// RsaVerifier verifies RSA signatures using the specified hash and options.
type RsaVerifier struct {
	h   crypto.Hash
	pss bool
}

func (v RsaVerifier) Verify(key *rsa.PublicKey, buf []byte, signature []byte) error {
	hasher := v.h.New()
	hasher.Write(buf)
	digest := hasher.Sum(nil)
	if v.pss {
		return rsa.VerifyPSS(key, v.h, digest, signature, &rsa.PSSOptions{Hash: v.h, SaltLength: rsa.PSSSaltLengthEqualsHash})
	}
	return rsa.VerifyPKCS1v15(key, v.h, digest, signature)
}

// VerifyRSA verifies the RSA signature for the given payload and header.
func VerifyRSA(key *rsa.PublicKey, payload, hdr, signature []byte, h crypto.Hash, pss bool, encoder Base64Encoder, encodePayload bool) error {
	return Verify[*rsa.PublicKey](key, payload, hdr, signature, RsaVerifier{h: h, pss: pss}, encoder, encodePayload)
}
