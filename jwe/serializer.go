package jwe

import (
	"encoding/json"

	"github.com/pkg/errors"
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
		return nil, errors.Wrap(err, "failed to copy protected header")
	}
	hcopy, err = hcopy.Merge(m.UnprotectedHeader)
	if err != nil {
		return nil, errors.Wrap(err, "failed to merge unprotected header")
	}
	hcopy, err = hcopy.Merge(recipient.Header)
	if err != nil {
		return nil, errors.Wrap(err, "failed to merge recipient header")
	}

	protected, err := EncodedHeader{Header: hcopy}.Base64Encode()
	if err != nil {
		return nil, errors.Wrap(err, "failed to encode header")
	}

	encryptedKey, err := recipient.EncryptedKey.Base64Encode()
	if err != nil {
		return nil, errors.Wrap(err, "failed to encode encryption key")
	}

	iv, err := m.InitializationVector.Base64Encode()
	if err != nil {
		return nil, errors.Wrap(err, "failed to encode iv")
	}

	cipher, err := m.CipherText.Base64Encode()
	if err != nil {
		return nil, errors.Wrap(err, "failed to encode cipher text")
	}

	tag, err := m.Tag.Base64Encode()
	if err != nil {
		return nil, errors.Wrap(err, "failed to encode tag")
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
