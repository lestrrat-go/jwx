package jwe

import (
	"context"
	"encoding/json"

	"github.com/pkg/errors"
)

// Serialize converts the message into a JWE compact serialize format byte buffer
func (s CompactSerialize) Serialize(m *Message) ([]byte, error) {
	if len(m.recipients) != 1 {
		return nil, errors.New("wrong number of recipients for compact serialization")
	}

	recipient := m.recipients[0]

	// The protected header must be a merge between the message-wide
	// protected header AND the recipient header

	// There's something wrong if m.protectedHeaders is nil, but
	// it could happen
	if m.protectedHeaders == nil {
		return nil, errors.New("invalid protected header")
	}

	hcopy, err := mergeHeaders(context.TODO(), nil, m.protectedHeaders)
	if err != nil {
		return nil, errors.Wrap(err, "failed to copy protected header")
	}
	hcopy, err = mergeHeaders(context.TODO(), hcopy, m.unprotectedHeaders)
	if err != nil {
		return nil, errors.Wrap(err, "failed to merge unprotected header")
	}
	hcopy, err = mergeHeaders(context.TODO(), hcopy, recipient.Headers)
	if err != nil {
		return nil, errors.Wrap(err, "failed to merge recipient header")
	}

	protected, err := hcopy.Encode()
	if err != nil {
		return nil, errors.Wrap(err, "failed to encode header")
	}

	encryptedKey, err := recipient.EncryptedKey.Base64Encode()
	if err != nil {
		return nil, errors.Wrap(err, "failed to encode encryption key")
	}

	iv, err := m.initializationVector.Base64Encode()
	if err != nil {
		return nil, errors.Wrap(err, "failed to encode iv")
	}

	cipher, err := m.cipherText.Base64Encode()
	if err != nil {
		return nil, errors.Wrap(err, "failed to encode cipher text")
	}

	tag, err := m.tag.Base64Encode()
	if err != nil {
		return nil, errors.Wrap(err, "failed to encode tag")
	}

	buf := append(append(append(append(append(append(append(append(protected, '.'), encryptedKey...), '.'), iv...), '.'), cipher...), '.'), tag...)
	return buf, nil
}

// Serialize converts the message into a JWE JSON serialize format byte buffer
func (s JSONSerialize) Serialize(m *Message) ([]byte, error) {
	if s.Pretty {
		return json.MarshalIndent(m, "", "  ")
	}
	return json.Marshal(m)
}
