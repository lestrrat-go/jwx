package jwsbb

import (
	"crypto"
	"crypto/rsa"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/internal/base64"
)

func RSAHashFuncFor(alg string) (crypto.Hash, bool, error) {
	switch alg {
	case "RS256":
		return crypto.SHA256, false, nil
	case "RS384":
		return crypto.SHA384, false, nil
	case "RS512":
		return crypto.SHA512, false, nil
	case "PS256":
		return crypto.SHA256, true, nil
	case "PS384":
		return crypto.SHA384, true, nil
	case "PS512":
		return crypto.SHA512, true, nil
	default:
		return 0, false, fmt.Errorf("unsupported RSA algorithm %s", alg)
	}
}

type RSASigner struct {
	h   crypto.Hash
	pss bool
}

func RSAPSSOptions(h crypto.Hash) rsa.PSSOptions {
	return rsa.PSSOptions{
		Hash:       h,
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	}
}

func NewRSASigner(h crypto.Hash, pss bool) RSASigner {
	return RSASigner{
		h:   h,
		pss: pss,
	}
}

func (s RSASigner) Sign(key *rsa.PrivateKey, payload []byte) ([]byte, error) {
	var opts crypto.SignerOpts = s.h
	if s.pss {
		rsaopts := RSAPSSOptions(s.h)
		opts = &rsaopts
	}
	return cryptosign(key, payload, s.h, opts)
}

func SignRSA(key *rsa.PrivateKey, raw []byte, h crypto.Hash, pss bool) ([]byte, error) {
	s := NewRSASigner(h, pss)
	return s.Sign(key, raw)
}

// RSAVerifier verifies RSA signatures using the specified hash and options.
type RSAVerifier struct {
	h   crypto.Hash
	pss bool
}

func (v RSAVerifier) Verify(key *rsa.PublicKey, buf []byte, signature []byte) error {
	hasher := v.h.New()
	hasher.Write(buf)
	digest := hasher.Sum(nil)
	if v.pss {
		return rsa.VerifyPSS(key, v.h, digest, signature, &rsa.PSSOptions{Hash: v.h, SaltLength: rsa.PSSSaltLengthEqualsHash})
	}
	return rsa.VerifyPKCS1v15(key, v.h, digest, signature)
}

// VerifyRSA verifies the RSA signature for the given payload and header.
func VerifyRSA(key *rsa.PublicKey, payload, hdr, signature []byte, h crypto.Hash, pss bool, encoder base64.Encoder, encodePayload bool) error {
	return Verify[*rsa.PublicKey](key, payload, hdr, signature, RSAVerifier{h: h, pss: pss}, encoder, encodePayload)
}
