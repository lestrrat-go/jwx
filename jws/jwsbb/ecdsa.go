package jwsbb

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/lestrrat-go/jwx/v3/internal/ecutil"
)

// UnpackASN1ECDSASignature unpacks an ASN.1 encoded ECDSA signature into r and s values.
func UnpackASN1ECDSASignature(signed []byte, r, s *big.Int) error {
	// Okay, this is silly, but hear me out. When we use the
	// crypto.Signer interface, the PrivateKey is hidden.
	// But we need some information about the key (its bit size).
	//
	// So while silly, we're going to have to make another call
	// here and fetch the Public key.
	// (This probably means that this information should be cached somewhere)
	var p struct {
		R *big.Int // TODO: get this from a pool?
		S *big.Int
	}
	if _, err := asn1.Unmarshal(signed, &p); err != nil {
		return fmt.Errorf(`failed to unmarshal ASN1 encoded signature: %w`, err)
	}

	r.Set(p.R)
	s.Set(p.S)
	return nil
}

func UnpackECDSASignature(signature []byte, pubkey *ecdsa.PublicKey, r, s *big.Int) error {
	keySize := ecutil.CalculateKeySize(pubkey.Curve)
	if len(signature) != keySize*2 {
		return fmt.Errorf(`invalid signature length for curve %q`, pubkey.Curve.Params().Name)
	}

	r.SetBytes(signature[:keySize])
	s.SetBytes(signature[keySize:])

	return nil
}

// EcdsaSigner signs payloads using ECDSA and the specified hash.
type EcdsaSigner struct {
	h crypto.Hash
}

func (es EcdsaSigner) Sign(payload []byte, key *ecdsa.PrivateKey) ([]byte, error) {
	hh := es.h.New()
	if _, err := hh.Write(payload); err != nil {
		return nil, fmt.Errorf(`failed to write payload using ecdsa: %w`, err)
	}
	digest := hh.Sum(nil)

	// Here be dragons: depending on if tcrypto.Signer

	// Sign and get r, s values
	r, s, err := ecdsa.Sign(rand.Reader, key, digest)
	if err != nil {
		return nil, fmt.Errorf(`failed to sign payload using ecdsa: %w`, err)
	}

	return PackECDSASignature(r, s, key.Curve.Params().BitSize)
}

// ECDSASignaturePairFromKey packs the r and s values from an ECDSA signature into a byte slice.
func PackECDSASignature(r *big.Int, sbig *big.Int, curveBits int) ([]byte, error) {
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

func SignECDSACryptoSigner(payload, hdr []byte, h crypto.Hash, encoder Base64Encoder, encodePayload bool, signer crypto.Signer) ([]byte, error) {
	// Because crypto/ecdsa.PrivateKey's crypto.Signer interface behaves differently
	// than the ecdsa.Sign function (it returns a ASN.1/DER encoded signature), we
	// need to handle the signing process manually.
	// (i.e. we can't just pass it to SignCryptoSigner() as we do with RSA keys)
	signed, err := SignCryptoSigner(payload, hdr, h, signer, h, encoder, encodePayload)
	if err != nil {
		return nil, fmt.Errorf(`failed to sign payload using crypto.Signer: %w`, err)
	}

	cpub := signer.Public()
	pubkey, ok := cpub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf(`expected *ecdsa.PublicKey, got %T`, pubkey)
	}
	curveBits := pubkey.Curve.Params().BitSize

	var r, s big.Int
	if err := UnpackASN1ECDSASignature(signed, &r, &s); err != nil {
		return nil, fmt.Errorf(`failed to unpack ASN1 encoded signature: %w`, err)
	}

	return PackECDSASignature(&r, &s, curveBits)
}

// EcdsaVerifier verifies ECDSA signatures using the specified hash.
type EcdsaVerifier struct {
	h crypto.Hash
}

func (v EcdsaVerifier) Verify(buf []byte, signature []byte, key *ecdsa.PublicKey) error {
	var r, s big.Int
	if err := UnpackECDSASignature(signature, key, &r, &s); err != nil {
		return fmt.Errorf("jwsbb.ECDSAVerifier: failed to unpack ECDSA signature: %w", err)
	}

	hasher := v.h.New()
	hasher.Write(buf)
	digest := hasher.Sum(nil)
	if !ecdsa.Verify(key, digest, &r, &s) {
		return fmt.Errorf("jwsbb.ECDSAVerifier: invalid ECDSA signature")
	}
	return nil
}

// VerifyECDSA verifies the ECDSA signature for the given payload and header.
func VerifyECDSA(payload, hdr, signature []byte, h crypto.Hash, encoder Base64Encoder, encodePayload bool, pubKey *ecdsa.PublicKey) error {
	return verify[*ecdsa.PublicKey](payload, hdr, signature, EcdsaVerifier{h: h}, encoder, encodePayload, pubKey)
}

func VerifyECDSACryptoSigner(payload, hdr, signature []byte, h crypto.Hash, encoder Base64Encoder, encodePayload bool, signer crypto.Signer) error {
	var pubkey *ecdsa.PublicKey
	switch cpub := signer.Public(); cpub := cpub.(type) {
	case ecdsa.PublicKey:
		pubkey = &cpub
	case *ecdsa.PublicKey:
		pubkey = cpub
	default:
		return fmt.Errorf(`jwsbb.VerifyECDSACryptoSigner: expected *ecdsa.PublicKey, got %T`, cpub)
	}

	hasher := h.New()
	hasher.Write(payload)
	digest := hasher.Sum(nil)

	var r, s big.Int
	if err := UnpackASN1ECDSASignature(signature, &r, &s); err != nil {
		return fmt.Errorf(`jwsbb.VerifyECDSACryptoSigner: failed to unpack ASN1 encoded signature: %w`, err)
	}

	if !ecdsa.Verify(pubkey, digest, &r, &s) {
		return fmt.Errorf(`jwsbb.VerifyECDSACryptoSigner: invalid ECDSA signature`)
	}
	return nil
}
