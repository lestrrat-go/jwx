package jwe

import (
	"bytes"
	"encoding/json"
	"errors"
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
	hcopy.Copy(&m.ProtectedHeader.Header)
	hcopy.Algorithm = recipient.Header.Algorithm
	for k, v := range recipient.Header.PrivateParams {
		hcopy.PrivateParams[k] = v
	}

	protected, err := EncodedHeader{Header: *hcopy}.Base64Encode()
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

	buf := bytes.Join(
		[][]byte{
			protected,
			encryptedKey,
			iv,
			cipher,
			tag,
		},
		[]byte{'.'},
	)
	return buf, nil
}

// Serialize converts the mssage into a JWE JSON serialize format byte buffer
func (s JSONSerialize) Serialize(m *Message) ([]byte, error) {
	if s.Pretty {
		return json.MarshalIndent(m, "", "  ")
	}
	return json.Marshal(m)
}
