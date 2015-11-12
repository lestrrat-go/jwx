// Package buffer provides a very thin wrapper around []byte buffer called
// `Buffer`, to provide functionalitites that are often used wthin the jwx
// related packages
package buffer

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
)

// Buffer wraps `[]byte` and provides functions that are often used in
// the jwx related packages. One notable difference is that while
// encoding/json marshalls `[]byte` using base64.StdEncoding, this
// module uses base64.RawURLEncoding as mandated by the spec
type Buffer []byte

// FromUint creates a `Buffer` from an unsigned int
func FromUint(v uint64) Buffer {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, v)
	return Buffer(bytes.TrimLeft(data, "\x00"))
}

func FromBase64(v []byte) (Buffer, error) {
	b := Buffer{}
	if err := b.Base64Decode(v); err != nil {
		return Buffer(nil), err
	}
	return b, nil
}

// Bytes returns the raw bytes that comprises the Buffer
func (b Buffer) Bytes() []byte {
	return []byte(b)
}

// Len returns the number of bytes that the Buffer holds
func (b Buffer) Len() int {
	return len(b)
}

func (b *Buffer) SetBytes(b2 []byte) {
	*b = make([]byte, len(b2))
	copy(*b, b2)
}

// Base64Encode encodes the contents of the Buffer using base64.RawURLEncoding
func (b Buffer) Base64Encode() ([]byte, error) {
	enc := base64.RawURLEncoding
	out := make([]byte, enc.EncodedLen(len(b)))
	enc.Encode(out, b)
	return out, nil
}

// Base64Decode decodes the contents of the Buffer using base64.RawURLEncoding
func (b *Buffer) Base64Decode(v []byte) error {
	enc := base64.RawURLEncoding
	out := make([]byte, enc.DecodedLen(len(v)))
	if _, err := enc.Decode(out, v); err != nil {
		return err
	}
	*b = Buffer(bytes.TrimRight(out, "\x00"))
	return nil
}

// MarshalJSON marshals the buffer into JSON format after encoding the buffer
// with base64.RawURLEncoding
func (b Buffer) MarshalJSON() ([]byte, error) {
	v, err := b.Base64Encode()
	if err != nil {
		return nil, err
	}
	return json.Marshal(string(v))
}

// UnmarshalJSON unmarshals from a JSON string into a Buffer, after decoding it 
// with base64.RawURLEncoding
func (b *Buffer) UnmarshalJSON(data []byte) error {
	var x string
	if err := json.Unmarshal(data, &x); err != nil {
		return err
	}
	return b.Base64Decode([]byte(x))
}
