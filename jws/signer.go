package jws

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"log"

	"github.com/lestrrat/go-jwx/buffer"
	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jwk"
)

func (m *MultiSign) MultiSign(payload []byte) (*Message, error) {
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
			log.Printf("%#v", k)
			protected.Jwk = k
			protected.KeyID = k.Kid()
		}

		protbuf, err := json.Marshal(protected)
		if err != nil {
			return nil, err
		}

		ss := append(append(protbuf, '.'), encoded...)

		sigbuf, err := signer.Sign(ss)
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
			Header:    *hdr,
			Protected: protbuf,
			Signature: buffer.Buffer(sigbuf),
		}

		msg.Signatures = append(msg.Signatures, sig)
	}

	return msg, nil
}

func (m *MultiSign) AddSigner(s Signer) {
	m.Signers = append(m.Signers, s)
}

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

func (s RsaSign) hash() (crypto.Hash, error) {
	var hash crypto.Hash
	switch s.Algorithm {
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
func (s RsaSign) Sign(payload []byte) ([]byte, error) {
	hash, err := s.hash()
	if err != nil {
		return nil, ErrUnsupportedAlgorithm
	}

	privkey := s.PrivateKey
	if privkey == nil {
		return nil, errors.New("cannot proceed with Sign(): no private key available")
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

// Verify checks that signature generated for `payload` matches `signature`.
// This fulfills the `Verifier` interface
func (s RsaSign) Verify(payload, signature []byte) error {
	hash, err := s.hash()
	if err != nil {
		return ErrUnsupportedAlgorithm
	}

	pubkey := s.PublicKey
	if pubkey == nil {
		if s.PrivateKey == nil {
			return errors.New("cannot proceed with Verify(): no private/public key available")
		}
		pubkey = &s.PrivateKey.PublicKey
	}

	h := hash.New()
	h.Write(payload)

	switch s.Algorithm {
	case jwa.RS256, jwa.RS384, jwa.RS512:
		return rsa.VerifyPKCS1v15(pubkey, hash, h.Sum(nil), signature)
	case jwa.PS256, jwa.PS384, jwa.PS512:
		return rsa.VerifyPSS(pubkey, hash, h.Sum(nil), signature, nil)
	default:
		return ErrUnsupportedAlgorithm
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

func (s EcdsaSign) Alg() jwa.SignatureAlgorithm {
	return s.Algorithm
}

func (s *EcdsaSign) Jwk() jwk.JSONWebKey {
	if s.JSONWebKey == nil {
		return nil
	}
	return s.JSONWebKey
}

func (s EcdsaSign) Kid() string {
	return s.KeyID
}

func (s EcdsaSign) hash() (crypto.Hash, error) {
	alg := s.Algorithm
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
// This fulfills the `Signer` interface
func (sign EcdsaSign) Sign(payload []byte) ([]byte, error) {
	hash, err := sign.hash()
	if err != nil {
		return nil, err
	}

	privkey := sign.PrivateKey
	if privkey == nil {
		return nil, errors.New("cannot proceed with Sign(): no private key available")
	}

	curveBits := privkey.Curve.Params().BitSize
	bitsizeOk := false
	switch hash {
	case crypto.SHA256:
		bitsizeOk = curveBits == 256
	case crypto.SHA384:
		bitsizeOk = curveBits == 384
	case crypto.SHA512:
		bitsizeOk = curveBits == 512
	}

	if !bitsizeOk {
		return nil, errors.New("key size does not match curve bit size")
	}

	h := hash.New()
	h.Write(payload)

	r, s, err := ecdsa.Sign(rand.Reader, privkey, h.Sum(nil))
	if err != nil {
		return nil, err
	}

	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes += 1
	}

	rBytes := r.Bytes()
	rBytesPadded := make([]byte, keyBytes)
	copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

	sBytes := s.Bytes()
	sBytesPadded := make([]byte, keyBytes)
	copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)

	out := append(rBytesPadded, sBytesPadded...)

	return out, nil
}

