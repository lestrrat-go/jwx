package jwe

import (
	"encoding/json"
	"errors"

	"github.com/lestrrat/go-jwx/buffer"
)

func NewRecipient() *Recipient {
	return &Recipient{
		Header: *NewHeader(),
	}
}

func NewHeader() *Header {
	return &Header{
		EssentialHeader: &EssentialHeader{},
		PrivateParams:   map[string]interface{}{},
	}
}

func (h1 *Header) Copy(h2 *Header) error {
	if h1 == nil {
		return errors.New("copy destination is nil")
	}
	if h2 == nil {
		return errors.New("copy target is nil")
	}

	h1.Algorithm = h2.Algorithm
	h1.ContentEncryption = h2.ContentEncryption
	h1.ContentType = h2.ContentType
	h1.Compression = h2.Compression
	h1.Critical = h2.Critical
	h1.Jwk = h2.Jwk
	h1.JwkSetURL = h2.JwkSetURL
	h1.KeyID = h2.KeyID
	h1.Type = h2.Type
	h1.X509Url = h2.X509Url
	h1.X509CertChain = h2.X509CertChain
	h1.X509CertThumbprint = h2.X509CertThumbprint
	h1.X509CertThumbprintS256 = h2.X509CertThumbprintS256

	for k, v := range h2.PrivateParams {
		h1.PrivateParams[k] = v
	}

	return nil
}

func (e EncodedHeader) Base64Encode() ([]byte, error) {
	buf, err := json.Marshal(e.Header)
	if err != nil {
		return nil, err
	}

	buf, err = buffer.Buffer(buf).Base64Encode()
	if err != nil {
		return nil, err
	}

	return buf, nil
}

func (e EncodedHeader) MarshalJSON() ([]byte, error) {
	buf, err := e.Base64Encode()
	if err != nil {
		return nil, err
	}
	return json.Marshal(string(buf))
}

func (e *EncodedHeader) UnmarshalJSON(buf []byte) error {
	b := buffer.Buffer{}
	// base646 json string -> json object representation of header
	if err := json.Unmarshal(buf, &b); err != nil {
		return err
	}

	if err := json.Unmarshal(b.Bytes(), &e.Header); err != nil {
		return err
	}

	return nil
}

func NewMessage() *Message {
	return &Message{}
}
