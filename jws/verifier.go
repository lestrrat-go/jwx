package jws

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"errors"
	"math/big"

	"github.com/lestrrat/go-jwx/jwa"
)

type payloadVerifier interface {
	PayloadVerify([]byte, []byte) error
}

func doMessageVerify(alg jwa.SignatureAlgorithm, v payloadVerifier, m *Message) error {
	var err error
	payload, err := m.Payload.Base64Encode()
	if err != nil {
		return err
	}
	for _, sig := range m.Signatures {
		if sig.ProtectedHeader.Algorithm != alg {
			continue
		}

		var phbuf []byte
		if sig.ProtectedHeader.Source.Len() > 0 {
			phbuf, err = sig.ProtectedHeader.Source.Base64Encode()
			if err != nil {
				continue
			}
		} else {
			phbuf, err = sig.ProtectedHeader.Base64Encode()
			if err != nil {
				continue
			}
		}
		siv := bytes.Join(
			[][]byte{
				phbuf,
				payload,
			},
			[]byte{'.'},
		)

		if err := v.PayloadVerify(siv, sig.Signature.Bytes()); err != nil {
			continue
		}

		return nil
	}

	return errors.New("none of the signatures could be verified")
}

func NewRsaVerify(alg jwa.SignatureAlgorithm, key *rsa.PublicKey) (*RsaVerify, error) {
	if key == nil {
		return nil, ErrMissingPublicKey
	}

	switch alg {
	case jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512:
	default:
		return nil, ErrUnsupportedAlgorithm
	}

	h, err := rsaHashForAlg(alg)
	if err != nil {
		return nil, ErrUnsupportedAlgorithm
	}

	return &RsaVerify{alg: alg, hash: h, pubkey: key}, nil
}

func (v RsaVerify) PayloadVerify(payload, signature []byte) error {
	pubkey := v.pubkey
	hfunc := v.hash
	h := hfunc.New()
	h.Write(payload)

	var err error
	switch v.alg {
	case jwa.RS256, jwa.RS384, jwa.RS512:
		err = rsa.VerifyPKCS1v15(pubkey, hfunc, h.Sum(nil), signature)
	case jwa.PS256, jwa.PS384, jwa.PS512:
		err = rsa.VerifyPSS(pubkey, hfunc, h.Sum(nil), signature, nil)
	}

	if err != nil {
		return err
	}
	return nil
}

// Verify checks that signature generated for `payload` matches `signature`.
// This fulfills the `Verifier` interface
func (v RsaVerify) Verify(m *Message) error {
	return doMessageVerify(v.alg, v, m)
}

func NewEcdsaVerify(alg jwa.SignatureAlgorithm, key *ecdsa.PublicKey) (*EcdsaVerify, error) {
	if key == nil {
		return nil, ErrMissingPublicKey
	}

	switch alg {
	case jwa.ES256, jwa.ES384, jwa.ES512:
	default:
		return nil, ErrUnsupportedAlgorithm
	}

	h, err := ecdsaHashForAlg(alg)
	if err != nil {
		return nil, ErrUnsupportedAlgorithm
	}

	return &EcdsaVerify{alg: alg, hash: h, pubkey: key}, nil
}

// Verify checks that signature generated for `payload` matches `signature`.
// This fulfills the `Verifier` interface
func (v EcdsaVerify) Verify(m *Message) error {
	return doMessageVerify(v.alg, v, m)
}

func (v EcdsaVerify) PayloadVerify(payload, signature []byte) error {
	pubkey := v.pubkey
	hfunc := v.hash
	keysiz := hfunc.Size()
	if len(signature) != 2*keysiz {
		return ErrInvalidEcdsaSignatureSize
	}

	h := hfunc.New()
	h.Write(payload)

	rv := (&big.Int{}).SetBytes(signature[:keysiz])
	sv := (&big.Int{}).SetBytes(signature[keysiz:])

	if !ecdsa.Verify(pubkey, h.Sum(nil), rv, sv) {
		return ErrInvalidSignature
	}
	return nil
}

type HmacVerify struct {
	signer *HmacSign
}

func NewHmacVerify(alg jwa.SignatureAlgorithm, key []byte) (*HmacVerify, error) {
	s, err := NewHmacSign(alg, key)
	if err != nil {
		return nil, err
	}
	return &HmacVerify{signer: s}, nil
}

// Verify checks that signature generated for `payload` matches `signature`.
// This fulfills the `Verifier` interface
func (v HmacVerify) Verify(m *Message) error {
	return doMessageVerify(v.signer.Algorithm, v, m)
}

func (v HmacVerify) PayloadVerify(payload, mac []byte) error {
	expected, err := v.signer.PayloadSign(payload)
	if err != nil {
		return err
	}

	if !hmac.Equal(mac, expected) {
		return ErrInvalidSignature
	}
	return nil
}
