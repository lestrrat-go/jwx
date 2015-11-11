// jwe implements JWE https://tools.ietf.org/html/rfc7516

package jwe

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/url"

	"github.com/lestrrat/go-jwx/buffer"
	"github.com/lestrrat/go-jwx/internal/emap"
	"github.com/lestrrat/go-jwx/jwa"
)

func debug(f string, args ...interface{}) {
	log.Printf(f, args...)
}

func (h *Header) Set(key string, value interface{}) error {
	switch key {
	case "alg":
		var v jwa.KeyEncryptionAlgorithm
		s, ok := value.(string)
		if ok {
			v = jwa.KeyEncryptionAlgorithm(s)
		} else {
			v, ok = value.(jwa.KeyEncryptionAlgorithm)
			if !ok {
				return ErrInvalidHeaderValue
			}
		}
		h.Algorithm = v
	case "enc":
		var v jwa.ContentEncryptionAlgorithm
		s, ok := value.(string)
		if ok {
			v = jwa.ContentEncryptionAlgorithm(s)
		} else {
			v, ok = value.(jwa.ContentEncryptionAlgorithm)
			if !ok {
				return ErrInvalidHeaderValue
			}
		}
		h.ContentEncryption = v
	case "cty":
		v, ok := value.(string)
		if !ok {
			return ErrInvalidHeaderValue
		}
		h.ContentType = v
	case "kid":
		v, ok := value.(string)
		if !ok {
			return ErrInvalidHeaderValue
		}
		h.KeyID = v
	case "typ":
		v, ok := value.(string)
		if !ok {
			return ErrInvalidHeaderValue
		}
		h.Type = v
	case "x5t":
		v, ok := value.(string)
		if !ok {
			return ErrInvalidHeaderValue
		}
		h.X509CertThumbprint = v
	case "x5t#256":
		v, ok := value.(string)
		if !ok {
			return ErrInvalidHeaderValue
		}
		h.X509CertThumbprintS256 = v
	case "x5c":
		v, ok := value.([]string)
		if !ok {
			return ErrInvalidHeaderValue
		}
		h.X509CertChain = v
	case "crit":
		v, ok := value.([]string)
		if !ok {
			return ErrInvalidHeaderValue
		}
		h.Critical = v
	case "jku":
		v, ok := value.(string)
		if !ok {
			return ErrInvalidHeaderValue
		}
		u, err := url.Parse(v)
		if err != nil {
			return ErrInvalidHeaderValue
		}
		h.JwkSetURL = u
	case "x5u":
		v, ok := value.(string)
		if !ok {
			return ErrInvalidHeaderValue
		}
		u, err := url.Parse(v)
		if err != nil {
			return ErrInvalidHeaderValue
		}
		h.X509Url = u
	default:
		h.PrivateParams[key] = value
	}
	return nil
}

func (h Header) MarshalJSON() ([]byte, error) {
	return emap.MergeMarshal(h.EssentialHeader, h.PrivateParams)
}

func (h *Header) UnmarshalJSON(data []byte) error {
	if h.EssentialHeader == nil {
		h.EssentialHeader = &EssentialHeader{}
	}
	if h.PrivateParams == nil {
		h.PrivateParams = map[string]interface{}{}
	}

	m := map[string]interface{}{}
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	for name, value := range m {
		if err := h.Set(name, value); err != nil {
			return err
		}
	}
	return nil
}

func Parse(buf []byte) (*Message, error) {
	buf = bytes.TrimSpace(buf)
	if len(buf) == 0 {
		return nil, errors.New("empty buffer")
	}

	if buf[0] == '{' {
		return parseJSON(buf)
	}
	return parseCompact(buf)
}

func ParseString(s string) (*Message, error) {
	return Parse([]byte(s))
}

func parseJSON(buf []byte) (*Message, error) {
	m := struct {
		*Message
		*Recipient
	}{}

	if err := json.Unmarshal(buf, &m); err != nil {
		return nil, err
	}

	// if the "signature" field exist, treat it as a flattened
	if m.Recipient != nil {
		if len(m.Message.Recipients) != 0 {
			return nil, errors.New("invalid message: mixed flattened/full json serialization")
		}

		m.Message.Recipients = []Recipient{*m.Recipient}
	}

	return m.Message, nil
}

func parseCompact(buf []byte) (*Message, error) {
	parts := bytes.Split(buf, []byte{'.'})
	if len(parts) != 5 {
		return nil, ErrInvalidCompactPartsCount
	}

	enc := base64.RawURLEncoding
	p0Len := enc.DecodedLen(len(parts[0]))
	p1Len := enc.DecodedLen(len(parts[1]))
	p2Len := enc.DecodedLen(len(parts[2]))
	p3Len := enc.DecodedLen(len(parts[3]))
	p4Len := enc.DecodedLen(len(parts[4]))

	out := make([]byte, p0Len+p1Len+p2Len+p3Len+p4Len)

	hdrbuf := buffer.Buffer(out[:p0Len])
	if _, err := enc.Decode(hdrbuf, parts[0]); err != nil {
		return nil, err
	}
	hdrbuf = bytes.TrimRight(hdrbuf, "\x00")

	hdr := NewHeader()
	if err := json.Unmarshal(hdrbuf, hdr); err != nil {
		return nil, err
	}

	enckeybuf := buffer.Buffer(out[p0Len : p0Len+p1Len])
	if _, err := enc.Decode(enckeybuf, parts[1]); err != nil {
		return nil, err
	}
	enckeybuf = bytes.TrimRight(enckeybuf, "\x00")

	ivbuf := buffer.Buffer(out[p0Len+p1Len : p0Len+p1Len+p2Len])
	if _, err := enc.Decode(ivbuf, parts[2]); err != nil {
		return nil, err
	}
	ivbuf = bytes.TrimRight(ivbuf, "\x00")

	ctbuf := buffer.Buffer(out[p0Len+p1Len+p2Len : p0Len+p1Len+p2Len+p3Len])
	if _, err := enc.Decode(ctbuf, parts[3]); err != nil {
		return nil, err
	}
	ctbuf = bytes.TrimRight(ctbuf, "\x00")

	tagbuf := buffer.Buffer(out[p0Len+p1Len+p2Len+p3Len : p0Len+p1Len+p2Len+p3Len+p4Len])
	if _, err := enc.Decode(tagbuf, parts[4]); err != nil {
		return nil, err
	}
	tagbuf = bytes.TrimRight(tagbuf, "\x00")

	m := NewMessage()
	m.Tag = tagbuf
	m.CipherText = ctbuf
	m.InitializationVector = ivbuf
	m.Recipients = []Recipient{
		Recipient{
			Header:       *hdr,
			EncryptedKey: enckeybuf,
		},
	}
	return m, nil
}

/*
func Encode(hdr, enckey, iv Base64Encoder, encrypt Encrypter) ([]byte, error) {

// BASE64URL(UTF8(JWE Protected Header)) || '.' ||
//   BASE64URL(JWE Encrypted Key) || '.' || BASE64URL(JWE Initialization
//   Vector) || '.' || BASE64URL(JWE Ciphertext) || '.' || BASE64URL(JWE
//   Authentication Tag).
	parts := make([][]byte, 5)
	hdrbuf, err := hdr.Base64Encode()
	if err != nil {
		return nil, err
	}
	parts[0] = hdrbuf

	keybuf, err := enckey.Base64Encode()
	if err != nil {
		return nil, err
	}
	parts[1] = keybuf

	ivbuf, err := iv.Base64Encode()
	if err != nil {
		return nil, err
	}
	parts[2] = ivbuf


//	msg := NewMessage()
//	msg.Crypter = append(msg.Crypter, NewRsaCrypt(contentalg, pubkey))


	return nil, nil
}
*/
