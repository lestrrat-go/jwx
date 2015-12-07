package jws

import (
	"encoding/json"
	"errors"

	"github.com/lestrrat/go-jwx/buffer"
)

// Serialize converts the mssage into a compact JSON format
func (s CompactSerialize) Serialize(m *Message) ([]byte, error) {
	if len(m.Signatures) != 1 {
		return nil, errors.New("wrong number of signatures for compact serialization")
	}

	signature := m.Signatures[0]

	hdr := NewHeader()
	if err := hdr.Copy(signature.ProtectedHeader.Header); err != nil {
		return nil, err
	}
	hdr, err := hdr.Merge(signature.PublicHeader)
	if err != nil {
		return nil, err
	}

	hdrbuf, err := hdr.Base64Encode()
	if err != nil {
		return nil, err
	}

	b64payload, err := m.Payload.Base64Encode()
	if err != nil {
		return nil, err
	}
	b64signature, err := buffer.Buffer(signature.Signature).Base64Encode()
	if err != nil {
		return nil, err
	}
	buf := append(append(append(append(hdrbuf, '.'), b64payload...), '.'), b64signature...)

	return buf, nil
}

// Serialize converts the mssage into a full JSON format
func (s JSONSerialize) Serialize(m *Message) ([]byte, error) {
	if s.Pretty {
		return json.MarshalIndent(m, "", "  ")
	}
	return json.Marshal(m)
}
