package jws

import "errors"

func (m Message) Verify(v Verifier) error {
	p, err := m.Payload.Base64Encode()
	if err != nil {
		return err
	}

	for _, sig := range m.Signatures {
		h, err := sig.Header.Base64Encode()
		if err != nil {
			return err
		}

		buf := append(append(h, '.'), p...)
		if err := v.Verify(buf, sig.Signature); err == nil {
			return nil
		}
	}

	return errors.New("none of the signatures could be verified")
}


