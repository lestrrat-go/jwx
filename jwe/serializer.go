package jwe

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"

	"github.com/pkg/errors"
)

var compactSerializationBufferPool = sync.Pool{
	New: func() interface{} {
		var b bytes.Buffer
		return &b
	},
}

func getCompactSerializationBuffer() *bytes.Buffer {
	return compactSerializationBufferPool.Get().(*bytes.Buffer)
}

func releaseCompactSerializationBuffer(b *bytes.Buffer) {
	b.Reset()
	compactSerializationBufferPool.Put(b)
}

// Compact encodes the given message into a JWE compact serialization format.
func Compact(m *Message, _ ...Option) ([]byte, error) {
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
	hcopy, err = mergeHeaders(context.TODO(), hcopy, recipient.Headers())
	if err != nil {
		return nil, errors.Wrap(err, "failed to merge recipient header")
	}

	protected, err := hcopy.Encode()
	if err != nil {
		return nil, errors.Wrap(err, "failed to encode header")
	}

	encryptedKey, err := recipient.EncryptedKey().Base64Encode()
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

	buf := getCompactSerializationBuffer()
	defer releaseCompactSerializationBuffer(buf)

	buf.Grow(len(protected) + len(encryptedKey) + len(iv) + len(cipher) + len(tag) + 4)
	buf.Write(protected)
	buf.WriteByte('.')
	buf.Write(encryptedKey)
	buf.WriteByte('.')
	buf.Write(iv)
	buf.WriteByte('.')
	buf.Write(cipher)
	buf.WriteByte('.')
	buf.Write(tag)

	return buf.Bytes(), nil
}

// JSON encodes the message into a JWE JSON serialization format.
func JSON(m *Message, options ...Option) ([]byte, error) {
	var pretty bool
	for _, option := range options {
		switch option.Name() {
		case optkeyPrettyJSONFormat:
			pretty = option.Value().(bool)
		}
	}

	if pretty {
		return json.MarshalIndent(m, "", "  ")
	}
	return json.Marshal(m)
}
