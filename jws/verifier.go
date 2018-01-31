package jws

import (
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
