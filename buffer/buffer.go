package buffer

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
)

type Buffer []byte

func FromUint(v uint64) Buffer {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, v)
	return Buffer(bytes.TrimLeft(data, "\x00"))
}

func (b Buffer) Bytes() []byte {
	return []byte(b)
}

func (b Buffer) Base64Encode() ([]byte, error) {
	enc := base64.RawURLEncoding
	out := make([]byte, enc.EncodedLen(len(b)))
	enc.Encode(out, b)
	return out, nil
}

func (b *Buffer) Base64Decode(v []byte) error {
	enc := base64.RawURLEncoding
	out := make([]byte, enc.DecodedLen(len(v)))
	enc.Decode(out, v)
	*b = Buffer(out)
	return nil
}

func (b Buffer) MarshalJSON() ([]byte, error) {
	return json.Marshal(b.Bytes())
}

func (b *Buffer) UnmarshalJSON(data []byte) error {
	var x []byte
	if err := json.Unmarshal(data, &x); err != nil {
		return err
	}

	*b = Buffer(x)
	return nil
}

// JsonDecode decodes the buffer into interface v
func (b Buffer) JsonDecode(v interface{}) error {
	return json.NewDecoder(bytes.NewBuffer(b)).Decode(v)
}
