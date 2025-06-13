package jwsbb

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/lestrrat-go/jwx/v3/internal/base64"
	"github.com/lestrrat-go/jwx/v3/internal/ecutil"
)

// UnpackASN1ECDSASignature unpacks an ASN.1 encoded ECDSA signature into r and s values.
// This is typically used when working with crypto.Signer interfaces that return ASN.1 encoded signatures.
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

// UnpackECDSASignature unpacks a JWS-format ECDSA signature into r and s values.
// The signature should be in the format specified by RFC 7515 (r||s as fixed-length byte arrays).
func UnpackECDSASignature(signature []byte, pubkey *ecdsa.PublicKey, r, s *big.Int) error {
	keySize := ecutil.CalculateKeySize(pubkey.Curve)
	if len(signature) != keySize*2 {
		return fmt.Errorf(`invalid signature length for curve %q`, pubkey.Curve.Params().Name)
	}

	r.SetBytes(signature[:keySize])
	s.SetBytes(signature[keySize:])

	return nil
}

// ecdsaSigner implements ECDSA signature generation using the specified hash algorithm.
type ecdsaSigner struct {
	h crypto.Hash
}

func (es ecdsaSigner) Sign(key *ecdsa.PrivateKey, payload []byte) ([]byte, error) {
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

// PackECDSASignature packs the r and s values from an ECDSA signature into a JWS-format byte slice.
// The output format follows RFC 7515: r||s as fixed-length byte arrays.
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

// newECDSASigner creates a new ECDSA signer with the specified hash algorithm.
func newECDSASigner(h crypto.Hash) ecdsaSigner {
	return ecdsaSigner{
		h: h,
	}
}

// SignECDSA generates an ECDSA signature for the given payload using the specified private key and hash.
// The raw parameter should be the pre-computed signing input (typically header.payload).
func SignECDSA(key *ecdsa.PrivateKey, raw []byte, h crypto.Hash) ([]byte, error) {
	s := newECDSASigner(h)
	return s.Sign(key, raw)
}

// SignECDSACryptoSigner generates an ECDSA signature using a crypto.Signer interface.
// This function works with hardware security modules and other crypto.Signer implementations.
// The signature is converted from ASN.1 format to JWS format (r||s).
func SignECDSACryptoSigner(signer crypto.Signer, raw []byte, h crypto.Hash) ([]byte, error) {
	signed, err := SignCryptoSigner(signer, raw, h, h)
	if err != nil {
		return nil, fmt.Errorf(`failed to sign payload using crypto.Signer: %w`, err)
	}

	return signECDSACryptoSigner(signer, signed)
}

func signECDSACryptoSigner(signer crypto.Signer, signed []byte) ([]byte, error) {
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

// ecdsaVerifier implements ECDSA signature verification using the specified hash algorithm.
type ecdsaVerifier struct {
	h crypto.Hash
}

func (v ecdsaVerifier) Verify(key *ecdsa.PublicKey, buf []byte, signature []byte) error {
	var r, s big.Int
	if err := UnpackECDSASignature(signature, key, &r, &s); err != nil {
		return fmt.Errorf("jwsbb.ECDSAVerifier: failed to unpack ECDSA signature: %w", err)
	}

	return ecdsaVerify(key, buf, v.h, &r, &s)
}

func ecdsaVerify(key *ecdsa.PublicKey, buf []byte, h crypto.Hash, r, s *big.Int) error {
	hasher := h.New()
	hasher.Write(buf)
	digest := hasher.Sum(nil)
	if !ecdsa.Verify(key, digest, r, s) {
		return fmt.Errorf("jwsbb.ECDSAVerifier: invalid ECDSA signature")
	}
	return nil
}

// VerifyECDSA verifies an ECDSA signature for the given payload and header.
// This function constructs the signing input by encoding the header and payload according to JWS specification,
// then verifies the signature using the specified public key and hash algorithm.
func VerifyECDSA(key *ecdsa.PublicKey, payload, hdr, signature []byte, h crypto.Hash, encoder base64.Encoder, encodePayload bool) error {
	return Verify[*ecdsa.PublicKey](key, payload, hdr, signature, ecdsaVerifier{h: h}, encoder, encodePayload)
}

// ecdsaCryptoSignerVerifier implements ECDSA signature verification for crypto.Signer interfaces.
type ecdsaCryptoSignerVerifier struct {
	h crypto.Hash
}

func (v ecdsaCryptoSignerVerifier) Verify(signer crypto.Signer, buf []byte, signature []byte) error {
	var pubkey *ecdsa.PublicKey
	switch cpub := signer.Public(); cpub := cpub.(type) {
	case ecdsa.PublicKey:
		pubkey = &cpub
	case *ecdsa.PublicKey:
		pubkey = cpub
	default:
		return fmt.Errorf(`jwsbb.VerifyECDSACryptoSigner: expected *ecdsa.PublicKey, got %T`, cpub)
	}

	var r, s big.Int
	if err := UnpackECDSASignature(signature, pubkey, &r, &s); err != nil {
		return fmt.Errorf("jwsbb.ECDSAVerifier: failed to unpack ASN.1 encoded ECDSA signature: %w", err)
	}

	return ecdsaVerify(pubkey, buf, v.h, &r, &s)
}

// VerifyECDSACryptoSigner verifies an ECDSA signature for crypto.Signer implementations.
// This function is useful for verifying signatures created by hardware security modules
// or other implementations of the crypto.Signer interface.
func VerifyECDSACryptoSigner(signer crypto.Signer, payload, hdr, signature []byte, h crypto.Hash, encoder base64.Encoder, encodePayload bool) error {
	return Verify[crypto.Signer](signer, payload, hdr, signature, ecdsaCryptoSignerVerifier{h: h}, encoder, encodePayload)
}
