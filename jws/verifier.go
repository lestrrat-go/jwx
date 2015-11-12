package jws

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"errors"

	"github.com/lestrrat/go-jwx/jwa"
)

type RsaVerify struct {
	alg    jwa.SignatureAlgorithm
	hash   crypto.Hash
	pubkey *rsa.PublicKey
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

	h, err := hashForAlg(alg)
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
	payload, err := m.Payload.Base64Encode()
	if err != nil {
		return err
	}
	for _, sig := range m.Signatures {
		if sig.ProtectedHeader.Algorithm != v.alg {
			continue
		}

		phbuf, err := sig.ProtectedHeader.Base64Encode()
		if err != nil {
			continue
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
