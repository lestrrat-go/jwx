package jws

func (c Compact) Verify(v Verifier) error {
	h, err := c.Header.Base64Encode()
	if err != nil {
		return err
	}

	p, err := c.Payload.Base64Encode()
	if err != nil {
		return err
	}

	buf := append(append(h, '.'), p...)
	if err := v.Verify(buf, c.Signature); err != nil {
		return err
	}
	return nil
}