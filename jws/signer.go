package jws

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"github.com/lestrrat/go-jwx/buffer"
	"github.com/lestrrat/go-jwx/internal/debug"
	"github.com/lestrrat/go-jwx/jwa"
	"github.com/pkg/errors"
)

// NewSigner creates a new MultiSign object with the given PayloadSigners.
// It is an alias to `NewMultiSign()`, but it exists so that it's clear
// to the end users that this is a generic signer that should be used
// for 99% of the cases
func NewSigner(signers ...PayloadSigner) *MultiSign {
	return NewMultiSign(signers...)
}

// NewMultiSign creates a new MultiSign object
func NewMultiSign(signers ...PayloadSigner) *MultiSign {
	ms := &MultiSign{}
	for _, s := range signers {
		ms.AddSigner(s)
	}
	return ms
}

// SignString takes a string payload, and creates a JWS signed message.
func (m *MultiSign) SignString(payload string) (*Message, error) {
	return m.Sign([]byte(payload))
}

// Sign takes a payload, and creates a JWS signed message.
func (m *MultiSign) Sign(payload []byte) (*Message, error) {
	encoded, err := buffer.Buffer(payload).Base64Encode()
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign")
	}

	msg := &Message{
		Payload:    buffer.Buffer(payload),
		Signatures: []Signature{},
	}
	for _, signer := range m.Signers {
		protected, err := NewHeader().Merge(signer.PublicHeaders())
		if err != nil {
			return nil, errors.Wrap(err, "failed to merge protected headers (1)")
		}
		protected, err = protected.Merge(signer.ProtectedHeaders())
		if err != nil {
			return nil, errors.Wrap(err, "failed to merge protected headers (2)")
		}
		protected.Algorithm = signer.SignatureAlgorithm()

		protbuf, err := protected.Base64Encode()
		if err != nil {
			return nil, errors.Wrap(err, "failed to base64 encode protected headers")
		}

		siv := append(append(protbuf, '.'), encoded...)

		sigbuf, err := signer.PayloadSign(siv)
		if err != nil {
			return nil, errors.Wrap(err, "failed to sign payload")
		}

		hdr, err := NewHeader().Merge(signer.PublicHeaders())
		if err != nil {
			return nil, errors.Wrap(err, "failed to merge public headers")
		}

		/*
			if hdr.KeyID == "" {
				if protected.KeyID != "" {
					// Use the JWK in the protected field...
					hdr.KeyID = protected.KeyID
				} else if signer.Kid() != "" {
					// Or, get it from the signer
					hdr.KeyID = signer.Kid()
				}
			}
		*/

		sig := Signature{
			PublicHeader:    hdr,
			ProtectedHeader: &EncodedHeader{Header: protected},
			Signature:       buffer.Buffer(sigbuf),
		}

		msg.Signatures = append(msg.Signatures, sig)
	}

	return msg, nil
}

// AddSigner takes a PayloadSigner and appends it to the list of signers
func (m *MultiSign) AddSigner(s PayloadSigner) {
	m.Signers = append(m.Signers, s)
}

// NewRsaSign creates a signer that signs payloads using the given private key
func NewRsaSign(alg jwa.SignatureAlgorithm, key *rsa.PrivateKey) (*RsaSign, error) {
	switch alg {
	case jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512:
	default:
		return nil, errors.Wrap(ErrUnsupportedAlgorithm, "unsupported algorithm while trying to create RSA signer")
	}

	pubhdr := NewHeader()
	protectedhdr := NewHeader()
	protectedhdr.Algorithm = alg
	return &RsaSign{
		PrivateKey: key,
		Protected:  protectedhdr,
		Public:     pubhdr,
	}, nil
}

// SignatureAlgorithm returns the algorithm being used for this signer
func (s RsaSign) SignatureAlgorithm() jwa.SignatureAlgorithm {
	return s.Protected.Algorithm
}

// PublicHeaders returns the public headers for this signer
func (s RsaSign) PublicHeaders() *Header {
	return s.Public
}

// ProtectedHeaders returns the protected headers for this signer
func (s RsaSign) ProtectedHeaders() *Header {
	return s.Protected
}

// SetPublicHeaders sets the public headers for this signer
func (s *RsaSign) SetPublicHeaders(h *Header) {
	s.Public = h
}

// SetProtectedHeaders sets the protected headers for this signer
func (s *RsaSign) SetProtectedHeaders(h *Header) {
	s.Protected = h
}

func rsaHashForAlg(alg jwa.SignatureAlgorithm) (crypto.Hash, error) {
	var hash crypto.Hash
	switch alg {
	case jwa.RS256, jwa.PS256:
		hash = crypto.SHA256
	case jwa.RS384, jwa.PS384:
		hash = crypto.SHA384
	case jwa.RS512, jwa.PS512:
		hash = crypto.SHA512
	default:
		return 0, ErrUnsupportedAlgorithm
	}

	return hash, nil
}

// PayloadSign generates a sign based on the Algorithm instance variable.
// This fulfills the `Signer` interface
func (s RsaSign) PayloadSign(payload []byte) ([]byte, error) {
	hash, err := rsaHashForAlg(s.SignatureAlgorithm())
	if err != nil {
		return nil, errors.Wrap(err, "unsupported algorithm to sign payload")
	}

	privkey := s.PrivateKey
	if privkey == nil {
		return nil, errors.Wrap(ErrMissingPrivateKey, "missing private key while signing payload")
	}

	h := hash.New()
	h.Write(payload)

	switch s.SignatureAlgorithm() {
	case jwa.RS256, jwa.RS384, jwa.RS512:
		return rsa.SignPKCS1v15(rand.Reader, privkey, hash, h.Sum(nil))
	case jwa.PS256, jwa.PS384, jwa.PS512:
		return rsa.SignPSS(rand.Reader, privkey, hash, h.Sum(nil), &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
		})
	default:
		return nil, ErrUnsupportedAlgorithm
	}
}

// NewEcdsaSign creates a signer that signs payloads using the given private key
func NewEcdsaSign(alg jwa.SignatureAlgorithm, key *ecdsa.PrivateKey) (*EcdsaSign, error) {
	switch alg {
	case jwa.ES256, jwa.ES384, jwa.ES512:
	default:
		return nil, ErrUnsupportedAlgorithm
	}

	pubhdr := NewHeader()
	protectedhdr := NewHeader()
	protectedhdr.Algorithm = alg
	return &EcdsaSign{
		PrivateKey: key,
		Protected:  protectedhdr,
		Public:     pubhdr,
	}, nil
}

// SignatureAlgorithm returns the algorithm being used for this signer
func (s EcdsaSign) SignatureAlgorithm() jwa.SignatureAlgorithm {
	return s.Protected.Algorithm
}

// PublicHeaders returns the public headers for this signer
func (s EcdsaSign) PublicHeaders() *Header {
	return s.Public
}

// ProtectedHeaders returns the protected headers for this signer
func (s EcdsaSign) ProtectedHeaders() *Header {
	return s.Protected
}

// SetPublicHeaders sets the public headers for this signer
func (s *EcdsaSign) SetPublicHeaders(h *Header) {
	s.Public = h
}

// SetProtectedHeaders sets the protected headers for this signer
func (s *EcdsaSign) SetProtectedHeaders(h *Header) {
	s.Protected = h
}

func ecdsaHashForAlg(alg jwa.SignatureAlgorithm) (crypto.Hash, error) {
	var hash crypto.Hash
	switch alg {
	case jwa.ES256:
		hash = crypto.SHA256
	case jwa.ES384:
		hash = crypto.SHA384
	case jwa.ES512:
		hash = crypto.SHA512
	default:
		return 0, ErrUnsupportedAlgorithm
	}

	return hash, nil
}

// PayloadSign generates a sign based on the Algorithm instance variable.
// This fulfills the `PayloadSigner` interface
func (s EcdsaSign) PayloadSign(payload []byte) ([]byte, error) {
	hash, err := ecdsaHashForAlg(s.SignatureAlgorithm())
	if err != nil {
		return nil, errors.Wrap(err, `failed to get ecdsa hash algorithm`)
	}

	privkey := s.PrivateKey
	if privkey == nil {
		return nil, errors.New("cannot proceed with Sign(): no private key available")
	}

	keysiz := hash.Size()
	curveBits := privkey.Curve.Params().BitSize
	if curveBits != keysiz*8 {
		return nil, errors.New("key size does not match curve bit size")
	}

	h := hash.New()
	h.Write(payload)
	signed := h.Sum(nil)
	if debug.Enabled {
		debug.Printf("payload = %s, signed -> %x", payload, signed)
	}

	r, v, err := ecdsa.Sign(rand.Reader, privkey, signed)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign payload using ecdsa")
	}

	out := make([]byte, keysiz*2)
	keys := [][]byte{r.Bytes(), v.Bytes()}
	for i, data := range keys {
		start := i * keysiz
		padlen := keysiz - len(data)
		copy(out[start+padlen:], data)
	}

	return out, nil
}

// NewHmacSign creates a symmetric signer that signs payloads using the given private key
func NewHmacSign(alg jwa.SignatureAlgorithm, key []byte) (*HmacSign, error) {
	h, err := hmacHashForAlg(alg)
	if err != nil {
		return nil, errors.Wrap(err, `failed to get ecdsa hash algorithm`)
	}

	pubhdr := NewHeader()
	protectedhdr := NewHeader()
	protectedhdr.Algorithm = alg
	return &HmacSign{
		hash:      h,
		Key:       key,
		Protected: protectedhdr,
		Public:    pubhdr,
	}, nil
}

func hmacHashForAlg(alg jwa.SignatureAlgorithm) (func() hash.Hash, error) {
	var h func() hash.Hash
	switch alg {
	case jwa.HS256:
		h = sha256.New
	case jwa.HS384:
		h = sha512.New384
	case jwa.HS512:
		h = sha512.New
	default:
		return nil, ErrUnsupportedAlgorithm
	}

	return h, nil
}

// PayloadSign generates a sign based on the Algorithm instance variable.
// This fulfills the `Signer` interface
func (s HmacSign) PayloadSign(payload []byte) ([]byte, error) {
	hfunc := s.hash
	h := hmac.New(hfunc, s.Key)
	h.Write(payload)
	b := h.Sum(nil)
	return b, nil
}

// SignatureAlgorithm returns the algorithm being used for this signer
func (s HmacSign) SignatureAlgorithm() jwa.SignatureAlgorithm {
	return s.Protected.Algorithm
}

// PublicHeaders returns the public headers for this signer
func (s HmacSign) PublicHeaders() *Header {
	return s.Public
}

// ProtectedHeaders returns the protected headers for this signer
func (s HmacSign) ProtectedHeaders() *Header {
	return s.Protected
}

// SetPublicHeaders sets the public headers for this signer
func (s *HmacSign) SetPublicHeaders(h *Header) {
	s.Public = h
}

// SetProtectedHeaders sets the protected headers for this signer
func (s *HmacSign) SetProtectedHeaders(h *Header) {
	s.Protected = h
}
