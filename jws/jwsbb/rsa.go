package jwsbb

import (
	"crypto"
	"crypto/rsa"
	"fmt"
)

// RSAHashFuncFor returns the appropriate hash function and PSS flag for the given RSA algorithm.
// Supported algorithms: RS256, RS384, RS512 (PKCS#1 v1.5) and PS256, PS384, PS512 (PSS).
// Returns the hash function, PSS flag, and an error if the algorithm is unsupported.
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

// rsaSigner implements RSA signature generation with support for both PKCS#1 v1.5 and PSS padding.
type rsaSigner struct {
	h   crypto.Hash
	pss bool
}

// RSAPSSOptions returns the PSS options for RSA-PSS signatures with the specified hash.
// The salt length is set to equal the hash length as per RFC 7518.
func RSAPSSOptions(h crypto.Hash) rsa.PSSOptions {
	return rsa.PSSOptions{
		Hash:       h,
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	}
}

// newRSASigner creates a new RSA signer with the specified hash function and padding mode.
// If pss is true, RSA-PSS padding is used; otherwise, PKCS#1 v1.5 padding is used.
func newRSASigner(h crypto.Hash, pss bool) rsaSigner {
	return rsaSigner{
		h:   h,
		pss: pss,
	}
}

func (s rsaSigner) Sign(key *rsa.PrivateKey, payload []byte) ([]byte, error) {
	var opts crypto.SignerOpts = s.h
	if s.pss {
		rsaopts := RSAPSSOptions(s.h)
		opts = &rsaopts
	}
	return cryptosign(key, payload, s.h, opts)
}

// SignRSA generates an RSA signature for the given payload using the specified private key and options.
// The raw parameter should be the pre-computed signing input (typically header.payload).
// If pss is true, RSA-PSS is used; otherwise, PKCS#1 v1.5 is used.
func SignRSA(key *rsa.PrivateKey, raw []byte, h crypto.Hash, pss bool) ([]byte, error) {
	s := newRSASigner(h, pss)
	return s.Sign(key, raw)
}

// rsaVerifier implements RSA signature verification with support for both PKCS#1 v1.5 and PSS padding.
type rsaVerifier struct {
	h   crypto.Hash
	pss bool
}

func newRSAVerifier(h crypto.Hash, pss bool) rsaVerifier {
	return rsaVerifier{
		h:   h,
		pss: pss,
	}
}

func (v rsaVerifier) Verify(key *rsa.PublicKey, buf []byte, signature []byte) error {
	hasher := v.h.New()
	hasher.Write(buf)
	digest := hasher.Sum(nil)
	if v.pss {
		return rsa.VerifyPSS(key, v.h, digest, signature, &rsa.PSSOptions{Hash: v.h, SaltLength: rsa.PSSSaltLengthEqualsHash})
	}
	return rsa.VerifyPKCS1v15(key, v.h, digest, signature)
}

// VerifyRSA verifies an RSA signature for the given payload and header.
// This function constructs the signing input by encoding the header and payload according to JWS specification,
// then verifies the signature using the specified public key and hash algorithm.
// If pss is true, RSA-PSS verification is used; otherwise, PKCS#1 v1.5 verification is used.
func VerifyRSA(key *rsa.PublicKey, payload, signature []byte, h crypto.Hash, pss bool) error {
	v := newRSAVerifier(h, pss)
	return v.Verify(key, payload, signature)
}
