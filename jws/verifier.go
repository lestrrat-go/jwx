package jws

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"math/big"

	"github.com/lestrrat/go-jwx/internal/debug"
	"github.com/lestrrat/go-jwx/jwa"
	"github.com/pkg/errors"
)

type payloadVerifier interface {
	payloadVerify([]byte, []byte) error
}

func doMessageVerify(alg jwa.SignatureAlgorithm, v payloadVerifier, m *Message) error {
	var err error
	payload, err := m.Payload.Base64Encode()
	if err != nil {
		return errors.Wrap(err, `failed to base64 encode payload`)
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
		siv := append(append(phbuf, '.'), payload...)

		if debug.Enabled {
			debug.Printf("siv = '%s'", siv)
		}
		if err := v.payloadVerify(siv, sig.Signature.Bytes()); err != nil {
			if debug.Enabled {
				debug.Printf("Payload verify failed: %s", err)
			}
			continue
		}

		return nil
	}

	return errors.New("none of the signatures could be verified")
}

// NewRsaVerify creates a new JWS verifier using the specified algorithm
// and the public key
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

func (v RsaVerify) payloadVerify(payload, signature []byte) error {
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
		return errors.Wrap(err, `failed to verify payload`)
	}
	return nil
}

// Verify checks that signature generated for `payload` matches `signature`.
// This fulfills the `Verifier` interface
func (v RsaVerify) Verify(m *Message) error {
	return doMessageVerify(v.alg, v, m)
}

// NewEcdsaVerify creates a new JWS verifier using the specified algorithm
// and the public key
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

func (v EcdsaVerify) payloadVerify(payload, signature []byte) error {
	pubkey := v.pubkey
	hfunc := v.hash
	keysiz := hfunc.Size()
	if len(signature) != 2*keysiz {
		return ErrInvalidEcdsaSignatureSize
	}

	rv := (&big.Int{}).SetBytes(signature[:keysiz])
	sv := (&big.Int{}).SetBytes(signature[keysiz:])

	h := hfunc.New()
	h.Write(payload)
	signed := h.Sum(nil)

	if debug.Enabled {
		debug.Printf("payload -> %s, signed -> %x", payload, signed)
	}

	if !ecdsa.Verify(pubkey, signed, rv, sv) {
		return ErrInvalidSignature
	}
	return nil
}

// NewHmacVerify creates a new JWS verifier using the specified algorithm
// and the public key
func NewHmacVerify(alg jwa.SignatureAlgorithm, key []byte) (*HmacVerify, error) {
	s, err := NewHmacSign(alg, key)
	if err != nil {
		return nil, errors.Wrap(err, `failed to generate HMAC signer`)
	}
	return &HmacVerify{signer: s}, nil
}

// Verify checks that signature generated for `payload` matches `signature`.
// This fulfills the `Verifier` interface
func (v HmacVerify) Verify(m *Message) error {
	return doMessageVerify(v.signer.SignatureAlgorithm(), v, m)
}

func (v HmacVerify) payloadVerify(payload, mac []byte) error {
	expected, err := v.signer.PayloadSign(payload)
	if err != nil {
		return errors.Wrap(err, `failed to generated signature`)
	}

	if !hmac.Equal(mac, expected) {
		return ErrInvalidSignature
	}
	return nil
}
