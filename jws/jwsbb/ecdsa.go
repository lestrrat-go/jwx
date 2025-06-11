package jwsbb

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"math/big"
)

// EcdsaSigner signs payloads using ECDSA and the specified hash.
type EcdsaSigner struct {
	h crypto.Hash
}

func (s EcdsaSigner) Sign(payload []byte, key *ecdsa.PrivateKey) ([]byte, error) {
	// Compute hash
	hh := s.h.New()
	if _, err := hh.Write(payload); err != nil {
		return nil, fmt.Errorf(`failed to write payload using ecdsa: %w`, err)
	}
	digest := hh.Sum(nil)

	// Sign and get r, s values
	r, sbig, err := ecdsa.Sign(rand.Reader, key, digest)
	if err != nil {
		return nil, fmt.Errorf(`failed to sign payload using ecdsa: %w`, err)
	}

	// Determine key size in bytes
	curveBits := key.Curve.Params().BitSize
	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes++
	}

	// Serialize r and s into fixed-length bytes
	rBytes := r.Bytes()
	rBytesPadded := make([]byte, keyBytes)
	copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

	sBytes := sbig.Bytes()
	sBytesPadded := make([]byte, keyBytes)
	copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)

	// Output as r||s
	return append(rBytesPadded, sBytesPadded...), nil
}

func SignECDSA(payload, hdr []byte, h crypto.Hash, encoder Base64Encoder, encodePayload bool, key *ecdsa.PrivateKey) ([]byte, error) {
	return sign[*ecdsa.PrivateKey](payload, hdr, EcdsaSigner{h: h}, encoder, encodePayload, key)
}

// EcdsaVerifier verifies ECDSA signatures using the specified hash.
type EcdsaVerifier struct {
	h crypto.Hash
}

func (v EcdsaVerifier) Verify(buf []byte, signature []byte, key *ecdsa.PublicKey) error {
	sigLen := len(signature)
	half := sigLen / 2
	var r, s big.Int
	r.SetBytes(signature[:half])
	s.SetBytes(signature[half:])
	hasher := v.h.New()
	hasher.Write(buf)
	digest := hasher.Sum(nil)
	if !ecdsa.Verify(key, digest, &r, &s) {
		return fmt.Errorf("invalid ECDSA signature")
	}
	return nil
}

// EdDSAVerifier verifies EdDSA (Ed25519) signatures.
type EdDSAVerifier struct{}

func (v EdDSAVerifier) Verify(buf []byte, signature []byte, key ed25519.PublicKey) error {
	if !ed25519.Verify(key, buf, signature) {
		return fmt.Errorf("invalid EdDSA signature")
	}
	return nil
}

// VerifyEdDSA verifies the EdDSA (Ed25519) signature for the given payload and header.
func VerifyEdDSA(payload, hdr, signature []byte, encoder Base64Encoder, encodePayload bool, pubKey ed25519.PublicKey) error {
	return verify[ed25519.PublicKey](payload, hdr, signature, EdDSAVerifier{}, encoder, encodePayload, pubKey)
}
