package jws

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"hash"

	"github.com/lestrrat/go-jwx/buffer"
	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jwk"
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

// Sign takes a payload, and creates a JWS signed message.
func (m *MultiSign) Sign(payload []byte) (*Message, error) {
	encoded, err := buffer.Buffer(payload).Base64Encode()
	if err != nil {
		return nil, err
	}

	msg := &Message{
		Payload:    buffer.Buffer(payload),
		Signatures: []Signature{},
	}
	for _, signer := range m.Signers {
		protected := NewHeader()
		protected.Algorithm = signer.Alg()

		if k := signer.Jwk(); k != nil {
			protected.Jwk = k
			protected.KeyID = k.Kid()
		}

		protbuf, err := json.Marshal(protected)
		if err != nil {
			return nil, err
		}

		ss := append(append(protbuf, '.'), encoded...)

		sigbuf, err := signer.PayloadSign(ss)
		if err != nil {
			return nil, err
		}

		hdr := NewHeader()

		if hdr.KeyID == "" {
			if protected.KeyID != "" {
				// Use the JWK in the protected field...
				hdr.KeyID = protected.KeyID
			} else if signer.Kid() != "" {
				// Or, get it from the signer
				hdr.KeyID = signer.Kid()
			}
		}

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
		return nil, ErrUnsupportedAlgorithm
	}

	return &RsaSign{
		Algorithm:  alg,
		PrivateKey: key,
	}, nil
}

func (s RsaSign) Alg() jwa.SignatureAlgorithm {
	return s.Algorithm
}

func (s *RsaSign) Jwk() jwk.JSONWebKey {
	if s.JSONWebKey == nil {
		return nil
	}
	return s.JSONWebKey
}

func (s *RsaSign) Kid() string {
	return s.KeyID
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

// Sign generates a sign based on the Algorithm instance variable.
// This fulfills the `Signer` interface
func (s RsaSign) PayloadSign(payload []byte) ([]byte, error) {
	hash, err := rsaHashForAlg(s.Algorithm)
	if err != nil {
		return nil, ErrUnsupportedAlgorithm
	}

	privkey := s.PrivateKey
	if privkey == nil {
		return nil, ErrMissingPrivateKey
	}

	h := hash.New()
	h.Write(payload)

	switch s.Algorithm {
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

func NewEcdsaSign(alg jwa.SignatureAlgorithm, key *ecdsa.PrivateKey) (*EcdsaSign, error) {
	switch alg {
	case jwa.ES256, jwa.ES384, jwa.ES512:
	default:
		return nil, ErrUnsupportedAlgorithm
	}

	return &EcdsaSign{
		Algorithm:  alg,
		PrivateKey: key,
	}, nil
}

func (sign EcdsaSign) Alg() jwa.SignatureAlgorithm {
	return sign.Algorithm
}

func (sign *EcdsaSign) Jwk() jwk.JSONWebKey {
	if sign.JSONWebKey == nil {
		return nil
	}
	return sign.JSONWebKey
}

func (sign EcdsaSign) Kid() string {
	return sign.KeyID
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

// Sign generates a sign based on the Algorithm instance variable.
// This fulfills the `PayloadSigner` interface
func (sign EcdsaSign) PayloadSign(payload []byte) ([]byte, error) {
	hash, err := ecdsaHashForAlg(sign.Algorithm)
	if err != nil {
		return nil, err
	}

	privkey := sign.PrivateKey
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

	r, s, err := ecdsa.Sign(rand.Reader, privkey, h.Sum(nil))
	if err != nil {
		return nil, err
	}

	out := make([]byte, keysiz*2)
	keys := [][]byte{r.Bytes(), s.Bytes()}
	for i, data := range keys {
		start := i * keysiz
		padlen := keysiz - len(data)
		copy(out[start+padlen:], data)
	}

	return out, nil
}

func NewHmacSign(alg jwa.SignatureAlgorithm, key []byte) (*HmacSign, error) {
	h, err := hmacHashForAlg(alg)
	if err != nil {
		return nil, err
	}

	return &HmacSign{
		Algorithm: alg,
		Key:       key,
		hash:      h,
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

func (s HmacSign) PayloadSign(payload []byte) ([]byte, error) {
	hfunc := s.hash
	h := hmac.New(hfunc, s.Key)
	h.Write(payload)
	b := h.Sum(nil)
	return b, nil
}

func (s HmacSign) Alg() jwa.SignatureAlgorithm {
	return s.Algorithm
}

func (s HmacSign) Jwk() jwk.JSONWebKey {
	if s.JSONWebKey == nil {
		return nil
	}
	return s.JSONWebKey
}

func (s HmacSign) Kid() string {
	return s.KeyID
}
