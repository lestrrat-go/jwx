// Package jwsbb provides the building blocks (hence the name "bb") for JWS operations.
// It should be thought of as a low-level API, almost akin to internal packages
// that should not be used directly by users of the jwx package. However, these exist
// to provide a more efficient way to perform JWS operations without the overhead of
// the higher-level jws package to power-users who know what they are doing.
//
// This package is currently considered EXPERIMENTAL, and the API may change
// without notice. It is not recommended to use this package unless you are
// fully aware of the implications of using it.
//
// All bb packages in jwx follow the same design principles:
// 1. Does minimal checking of input parameters (for performance); callers need to ensure that the parameters are valid.
// 2. All exported functions are stringly typed (i.e. they do not take interface{} parameters unless they absolutely have to).
// 3. Does not rely on other public jwx packages (they are standalone, except for internal packages).
package jwsbb

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"hash"
	"math/big"

	"github.com/lestrrat-go/jwx/v3/internal/pool"
	"github.com/lestrrat-go/jwx/v3/internal/tokens"
)

type Base64Encoder interface {
	// AppendEncode appends the Base64URL encoded version of the input to the output.
	AppendEncode(dst, src []byte) []byte
}

// Signer is an interface that defines the method for signing payloads.
type Signer[K any] interface {
	Sign(payload []byte, key K) ([]byte, error)
}

func cryptosign(payload []byte, hash crypto.Hash, signer crypto.Signer, opts crypto.SignerOpts) ([]byte, error) {
	h := hash.New()
	if _, err := h.Write(payload); err != nil {
		return nil, fmt.Errorf(`failed to write payload to hash: %w`, err)
	}
	return signer.Sign(rand.Reader, h.Sum(nil), opts)
}

type HmacSigner struct {
	hfunc func() hash.Hash
}

func (s HmacSigner) Sign(payload []byte, key []byte) ([]byte, error) {
	fmt.Printf("HMAC: signing %q\n", payload)
	h := hmac.New(s.hfunc, key)
	if _, err := h.Write(payload); err != nil {
		return nil, fmt.Errorf(`failed to write payload using hmac: %w`, err)
	}
	return h.Sum(nil), nil
}

type RsaSigner struct {
	h   crypto.Hash
	pss bool
}

func (s RsaSigner) Sign(payload []byte, key *rsa.PrivateKey) ([]byte, error) {
	var opts crypto.SignerOpts = s.h
	if s.pss {
		opts = &rsa.PSSOptions{
			Hash:       s.h,
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		}
	}
	return cryptosign(payload, s.h, key, opts)
}

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

// EdDSASigner signs payloads using EdDSA (Ed25519).
type EdDSASigner struct{}

func (s EdDSASigner) Sign(payload []byte, key ed25519.PrivateKey) ([]byte, error) {
	// Ed25519 signs the raw payload directly
	return ed25519.Sign(key, payload), nil
}

// SignHMAC generates a single signature for the given payload using the
// specified hash function and key.
func SignHMAC(payload, hdr []byte, hfunc func() hash.Hash, encoder Base64Encoder, encodePayload bool, key []byte) ([]byte, error) {
	return sign[[]byte](payload, hdr, HmacSigner{hfunc: hfunc}, encoder, encodePayload, key)
}

func SignRSA(payload, hdr []byte, h crypto.Hash, pss bool, encoder Base64Encoder, encodePayload bool, key *rsa.PrivateKey) ([]byte, error) {
	return sign[*rsa.PrivateKey](payload, hdr, RsaSigner{h: h, pss: pss}, encoder, encodePayload, key)
}

func SignECDSA(payload, hdr []byte, h crypto.Hash, encoder Base64Encoder, encodePayload bool, key *ecdsa.PrivateKey) ([]byte, error) {
	return sign[*ecdsa.PrivateKey](payload, hdr, EcdsaSigner{h: h}, encoder, encodePayload, key)
}

func SignEdDSA(payload, hdr []byte, encoder Base64Encoder, encodePayload bool, key ed25519.PrivateKey) ([]byte, error) {
	return sign[ed25519.PrivateKey](payload, hdr, EdDSASigner{}, encoder, encodePayload, key)
}

func sign[K any](payload, hdr []byte, signer Signer[K], encoder Base64Encoder, encodePayload bool, key K) ([]byte, error) {
	buf := pool.ByteSlice().GetCapacity(len(payload) + len(hdr) + 1)

	buf = encoder.AppendEncode(buf, hdr)
	buf = append(buf, tokens.Period)
	if encodePayload {
		buf = encoder.AppendEncode(buf, payload)
	} else {
		buf = append(buf, payload...)
	}

	defer pool.ByteSlice().Put(buf)
	return signer.Sign(buf, key)
}

type Verifier[K any] interface {
	Verify(buf []byte, signature []byte, key K) error
}

type HmacVerifier struct {
	hfunc func() hash.Hash
}

func (v HmacVerifier) Verify(buf []byte, signature []byte, key []byte) error {
	expected := hmac.New(v.hfunc, key)
	expected.Write(buf)
	if !hmac.Equal(signature, expected.Sum(nil)) {
		return fmt.Errorf("invalid HMAC signature")
	}
	return nil
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

// VerifyHMAC verifies the HMAC signature for the given payload and header.
func VerifyHMAC(payload, hdr, signature []byte, hfunc func() hash.Hash, encoder Base64Encoder, encodePayload bool, key []byte) error {
	return verify[[]byte](payload, hdr, signature, HmacVerifier{hfunc: hfunc}, encoder, encodePayload, key)
}

// VerifyRSA verifies the RSA signature for the given payload and header.
func VerifyRSA(payload, hdr, signature []byte, h crypto.Hash, pss bool, encoder Base64Encoder, encodePayload bool, pubKey *rsa.PublicKey) error {
	return verify[*rsa.PublicKey](payload, hdr, signature, RsaVerifier{h: h, pss: pss}, encoder, encodePayload, pubKey)
}

// VerifyECDSA verifies the ECDSA signature for the given payload and header.
func VerifyECDSA(payload, hdr, signature []byte, h crypto.Hash, encoder Base64Encoder, encodePayload bool, pubKey *ecdsa.PublicKey) error {
	return verify[*ecdsa.PublicKey](payload, hdr, signature, EcdsaVerifier{h: h}, encoder, encodePayload, pubKey)
}

// VerifyEdDSA verifies the EdDSA (Ed25519) signature for the given payload and header.
func VerifyEdDSA(payload, hdr, signature []byte, encoder Base64Encoder, encodePayload bool, pubKey ed25519.PublicKey) error {
	return verify[ed25519.PublicKey](payload, hdr, signature, EdDSAVerifier{}, encoder, encodePayload, pubKey)
}

func verify[K any](payload, hdr, signature []byte, verifier Verifier[K], encoder Base64Encoder, encodePayload bool, key K) error {
	buf := pool.ByteSlice().GetCapacity(len(payload) + len(hdr) + 1)

	buf = encoder.AppendEncode(buf, hdr)
	buf = append(buf, tokens.Period)
	if encodePayload {
		buf = encoder.AppendEncode(buf, payload)
	} else {
		buf = append(buf, payload...)
	}

	defer pool.ByteSlice().Put(buf)
	return verifier.Verify(buf, signature, key)
}
