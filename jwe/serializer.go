package jwe

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Serialize converts the mssage into a JWE compact serialize format byte buffer
func (s CompactSerialize) Serialize(m *Message) ([]byte, error) {
	if len(m.Recipients) != 1 {
		return nil, errors.New("wrong number of recipients for compact serialization")
	}

	recipient := m.Recipients[0]

	// The protected header must be a merge between the message-wide
	// protected header AND the recipient header
	hcopy := NewHeader()
	// There's something wrong if m.ProtectedHeader.Header is nil, but
	// it could happen
	if m.ProtectedHeader == nil || m.ProtectedHeader.Header == nil {
		return nil, errors.New("invalid protected header")
	}
	err := hcopy.Copy(m.ProtectedHeader.Header)
	if err != nil {
		return nil, fmt.Errorf("copy header failed (protected): %s", err)
	}
	hcopy, err = hcopy.Merge(m.UnprotectedHeader)
	if err != nil {
		return nil, fmt.Errorf("merge header failed (unprotected): %s", err)
	}
	hcopy, err = hcopy.Merge(recipient.Header)
	if err != nil {
		return nil, fmt.Errorf("merge header failed (recipient): %s", err)
	}

	protected, err := EncodedHeader{Header: hcopy}.Base64Encode()
	if err != nil {
		return nil, err
	}

	encryptedKey, err := recipient.EncryptedKey.Base64Encode()
	if err != nil {
		return nil, err
	}

	iv, err := m.InitializationVector.Base64Encode()
	if err != nil {
		return nil, err
	}

	cipher, err := m.CipherText.Base64Encode()
	if err != nil {
		return nil, err
	}

	tag, err := m.Tag.Base64Encode()
	if err != nil {
		return nil, err
	}

	buf := append(append(append(append(append(append(append(append(protected, '.'), encryptedKey...), '.'), iv...), '.'), cipher...), '.'), tag...)
	return buf, nil
}

// Serialize converts the mssage into a JWE JSON serialize format byte buffer
func (s JSONSerialize) Serialize(m *Message) ([]byte, error) {
	if s.Pretty {
		return json.MarshalIndent(m, "", "  ")
	}
	return json.Marshal(m)
}
