package jws

import (
	"encoding/json"

	"github.com/lestrrat/go-jwx/buffer"
	"github.com/pkg/errors"
)

// Serialize converts the mssage into a compact JSON format
func (s CompactSerialize) Serialize(m *Message) ([]byte, error) {
	if len(m.Signatures) != 1 {
		return nil, errors.New("wrong number of signatures for compact serialization")
	}

	signature := m.Signatures[0]

	hdr := NewHeader()
	if err := hdr.Copy(signature.ProtectedHeader.Header); err != nil {
		return nil, errors.Wrap(err, `failed to copy from protected headers`)
	}
	hdr, err := hdr.Merge(signature.PublicHeader)
	if err != nil {
		return nil, errors.Wrap(err, `failed to merge with public headers`)
	}

	hdrbuf, err := hdr.Base64Encode()
	if err != nil {
		return nil, errors.Wrap(err, `failed to base64 encode headers`)
	}

	b64payload, err := m.Payload.Base64Encode()
	if err != nil {
		return nil, errors.Wrap(err, `failed to base64 encode payload`)
	}
	b64signature, err := buffer.Buffer(signature.Signature).Base64Encode()
	if err != nil {
		return nil, errors.Wrap(err, `failed to base64 encode signature`)
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
