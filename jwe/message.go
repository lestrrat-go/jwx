package jwe

import (
	"bytes"
	"compress/flate"
	"encoding/json"
	"net/url"

	"github.com/lestrrat/go-jwx/buffer"
	"github.com/lestrrat/go-jwx/internal/debug"
	"github.com/lestrrat/go-jwx/internal/emap"
	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jwk"
	"github.com/pkg/errors"
)

// NewRecipient creates a Recipient object
func NewRecipient() *Recipient {
	return &Recipient{
		Header: NewHeader(),
	}
}

// NewHeader creates a new Header object
func NewHeader() *Header {
	return &Header{
		EssentialHeader: &EssentialHeader{},
		PrivateParams:   map[string]interface{}{},
	}
}

// NewEncodedHeader creates a new encoded Header object
func NewEncodedHeader() *EncodedHeader {
	return &EncodedHeader{
		Header: NewHeader(),
	}
}

// Get returns the header key
func (h *Header) Get(key string) (interface{}, error) {
	switch key {
	case "alg":
		return h.Algorithm, nil
	case "apu":
		return h.AgreementPartyUInfo, nil
	case "apv":
		return h.AgreementPartyVInfo, nil
	case "enc":
		return h.ContentEncryption, nil
	case "epk":
		return h.EphemeralPublicKey, nil
	case "cty":
		return h.ContentType, nil
	case "kid":
		return h.KeyID, nil
	case "typ":
		return h.Type, nil
	case "x5t":
		return h.X509CertThumbprint, nil
	case "x5t#256":
		return h.X509CertThumbprintS256, nil
	case "x5c":
		return h.X509CertChain, nil
	case "crit":
		return h.Critical, nil
	case "jku":
		return h.JwkSetURL, nil
	case "x5u":
		return h.X509Url, nil
	default:
		v, ok := h.PrivateParams[key]
		if !ok {
			return nil, errors.New("invalid header name")
		}
		return v, nil
	}
}

// Set sets the value of the given key to the given value. If it's
// one of the known keys, it will be set in EssentialHeader field.
// Otherwise, it is set in PrivateParams field.
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
				return errors.Wrap(ErrInvalidHeaderValue, "invalid header value for 'alg'")
			}
		}
		h.Algorithm = v
	case "apu":
		var v buffer.Buffer
		switch value.(type) {
		case buffer.Buffer:
			v = value.(buffer.Buffer)
		case []byte:
			v = buffer.Buffer(value.([]byte))
		case string:
			v = buffer.Buffer(value.(string))
		default:
			return errors.Wrap(ErrInvalidHeaderValue, "invalid header value for 'apu'")
		}
		h.AgreementPartyUInfo = v
	case "apv":
		var v buffer.Buffer
		switch value.(type) {
		case buffer.Buffer:
			v = value.(buffer.Buffer)
		case []byte:
			v = buffer.Buffer(value.([]byte))
		case string:
			v = buffer.Buffer(value.(string))
		default:
			return errors.Wrap(ErrInvalidHeaderValue, "invalid header value for 'apv'")
		}
		h.AgreementPartyVInfo = v
	case "enc":
		var v jwa.ContentEncryptionAlgorithm
		s, ok := value.(string)
		if ok {
			v = jwa.ContentEncryptionAlgorithm(s)
		} else {
			v, ok = value.(jwa.ContentEncryptionAlgorithm)
			if !ok {
				return errors.Wrap(ErrInvalidHeaderValue, "invalid header value for 'enc'")
			}
		}
		h.ContentEncryption = v
	case "cty":
		v, ok := value.(string)
		if !ok {
			return errors.Wrap(ErrInvalidHeaderValue, "invalid header value for 'cty'")
		}
		h.ContentType = v
	case "epk":
		v, ok := value.(*jwk.EcdsaPublicKey)
		if !ok {
			return errors.Wrap(ErrInvalidHeaderValue, "invalid header value for 'epk'")
		}
		h.EphemeralPublicKey = v
	case "kid":
		v, ok := value.(string)
		if !ok {
			return errors.Wrap(ErrInvalidHeaderValue, "invalid header value for 'kid'")
		}
		h.KeyID = v
	case "typ":
		v, ok := value.(string)
		if !ok {
			return errors.Wrap(ErrInvalidHeaderValue, "invalid header value for 'typ'")
		}
		h.Type = v
	case "x5t":
		v, ok := value.(string)
		if !ok {
			return errors.Wrap(ErrInvalidHeaderValue, "invalid header value for 'x5t'")
		}
		h.X509CertThumbprint = v
	case "x5t#256":
		v, ok := value.(string)
		if !ok {
			return errors.Wrap(ErrInvalidHeaderValue, "invalid header value for 'x5t#256'")
		}
		h.X509CertThumbprintS256 = v
	case "x5c":
		v, ok := value.([]string)
		if !ok {
			return errors.Wrap(ErrInvalidHeaderValue, "invalid header value for 'x5c'")
		}
		h.X509CertChain = v
	case "crit":
		v, ok := value.([]string)
		if !ok {
			return errors.Wrap(ErrInvalidHeaderValue, "invalid header value for 'crit'")
		}
		h.Critical = v
	case "jku":
		v, ok := value.(string)
		if !ok {
			return errors.Wrap(ErrInvalidHeaderValue, "invalid header value for 'jku'")
		}
		u, err := url.Parse(v)
		if err != nil {
			return errors.Wrap(errors.Wrap(err, "failed to parse new value for 'jku' header"), "invalid header value")
		}
		h.JwkSetURL = u
	case "x5u":
		v, ok := value.(string)
		if !ok {
			return errors.Wrap(ErrInvalidHeaderValue, "invalid header value for 'x5u'")
		}
		u, err := url.Parse(v)
		if err != nil {
			return errors.Wrap(errors.Wrap(err, "failed to parse new value for 'x5u' header"), "invalid header value")
		}
		h.X509Url = u
	default:
		h.PrivateParams[key] = value
	}
	return nil
}

// Merge merges the current header with another.
func (h *Header) Merge(h2 *Header) (*Header, error) {
	if h2 == nil {
		return nil, errors.New("merge target is nil")
	}

	h3 := NewHeader()
	if err := h3.Copy(h); err != nil {
		return nil, errors.Wrap(err, "failed to copy header values")
	}

	h3.EssentialHeader.Merge(h2.EssentialHeader)

	for k, v := range h2.PrivateParams {
		h3.PrivateParams[k] = v
	}

	return h3, nil
}

// Merge merges the current header with another.
func (h *EssentialHeader) Merge(h2 *EssentialHeader) {
	if h2.AgreementPartyUInfo.Len() != 0 {
		h.AgreementPartyUInfo = h2.AgreementPartyUInfo
	}

	if h2.AgreementPartyVInfo.Len() != 0 {
		h.AgreementPartyVInfo = h2.AgreementPartyVInfo
	}

	if h2.Algorithm != "" {
		h.Algorithm = h2.Algorithm
	}

	if h2.ContentEncryption != "" {
		h.ContentEncryption = h2.ContentEncryption
	}

	if h2.ContentType != "" {
		h.ContentType = h2.ContentType
	}

	if h2.Compression != "" {
		h.Compression = h2.Compression
	}

	if h2.Critical != nil {
		h.Critical = h2.Critical
	}

	if h2.EphemeralPublicKey != nil {
		h.EphemeralPublicKey = h2.EphemeralPublicKey
	}

	if h2.Jwk != nil {
		h.Jwk = h2.Jwk
	}

	if h2.JwkSetURL != nil {
		h.JwkSetURL = h2.JwkSetURL
	}

	if h2.KeyID != "" {
		h.KeyID = h2.KeyID
	}

	if h2.Type != "" {
		h.Type = h2.Type
	}

	if h2.X509Url != nil {
		h.X509Url = h2.X509Url
	}

	if h2.X509CertChain != nil {
		h.X509CertChain = h2.X509CertChain
	}

	if h2.X509CertThumbprint != "" {
		h.X509CertThumbprint = h2.X509CertThumbprint
	}

	if h2.X509CertThumbprintS256 != "" {
		h.X509CertThumbprintS256 = h2.X509CertThumbprintS256
	}
}

// Copy copies the other heder over this one
func (h *Header) Copy(h2 *Header) error {
	if h == nil {
		return errors.New("copy destination is nil")
	}
	if h2 == nil {
		return errors.New("copy target is nil")
	}

	h.EssentialHeader.Copy(h2.EssentialHeader)

	for k, v := range h2.PrivateParams {
		h.PrivateParams[k] = v
	}

	return nil
}

// Copy copies the other heder over this one
func (h *EssentialHeader) Copy(h2 *EssentialHeader) {
	h.AgreementPartyUInfo = h2.AgreementPartyUInfo
	h.AgreementPartyVInfo = h2.AgreementPartyVInfo
	h.Algorithm = h2.Algorithm
	h.ContentEncryption = h2.ContentEncryption
	h.ContentType = h2.ContentType
	h.Compression = h2.Compression
	h.Critical = h2.Critical
	h.EphemeralPublicKey = h2.EphemeralPublicKey
	h.Jwk = h2.Jwk
	h.JwkSetURL = h2.JwkSetURL
	h.KeyID = h2.KeyID
	h.Type = h2.Type
	h.X509Url = h2.X509Url
	h.X509CertChain = h2.X509CertChain
	h.X509CertThumbprint = h2.X509CertThumbprint
	h.X509CertThumbprintS256 = h2.X509CertThumbprintS256
}

// MarshalJSON generates the JSON representation of this header
func (h Header) MarshalJSON() ([]byte, error) {
	return emap.MergeMarshal(h.EssentialHeader, h.PrivateParams)
}

// UnmarshalJSON parses the JSON buffer into a Header
func (h *Header) UnmarshalJSON(data []byte) error {
	if h.EssentialHeader == nil {
		h.EssentialHeader = &EssentialHeader{}
	}
	if h.PrivateParams == nil {
		h.PrivateParams = map[string]interface{}{}
	}

	if err := json.Unmarshal(data, h.EssentialHeader); err != nil {
		return errors.Wrap(err, "failed to parse JSON (essential) headers")
	}

	m := map[string]interface{}{}
	if err := json.Unmarshal(data, &m); err != nil {
		return errors.Wrap(err, "failed to parse JSON headers")
	}
	for _, n := range []string{"alg", "apu", "apv", "enc", "cty", "zip", "crit", "epk", "jwk", "jku", "kid", "typ", "x5u", "x5c", "x5t", "x5t#S256"} {
		delete(m, n)
	}

	for name, value := range m {
		if err := h.Set(name, value); err != nil {
			return errors.Wrap(err, "failed to set header field '"+name+"'")
		}
	}
	return nil
}

// Base64Encode creates the base64 encoded version of the JSON
// representation of this header
func (e EncodedHeader) Base64Encode() ([]byte, error) {
	buf, err := json.Marshal(e.Header)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal encoded header into JSON")
	}

	buf, err = buffer.Buffer(buf).Base64Encode()
	if err != nil {
		return nil, errors.Wrap(err, "failed to base64 encode encoded header")
	}

	return buf, nil
}

// MarshalJSON generates the JSON representation of this header
func (e EncodedHeader) MarshalJSON() ([]byte, error) {
	buf, err := e.Base64Encode()
	if err != nil {
		return nil, errors.Wrap(err, "failed to base64 encode encoded header")
	}
	return json.Marshal(string(buf))
}

// UnmarshalJSON parses the JSON buffer into a Header
func (e *EncodedHeader) UnmarshalJSON(buf []byte) error {
	b := buffer.Buffer{}
	// base646 json string -> json object representation of header
	if err := json.Unmarshal(buf, &b); err != nil {
		return errors.Wrap(err, "failed to unmarshal buffer")
	}

	if err := json.Unmarshal(b.Bytes(), &e.Header); err != nil {
		return errors.Wrap(err, "failed to unmarshal buffer")
	}

	return nil
}

// NewMessage creates a new message
func NewMessage() *Message {
	return &Message{
		ProtectedHeader:   NewEncodedHeader(),
		UnprotectedHeader: NewHeader(),
	}
}

// Decrypt decrypts the message using the specified algorithm and key
func (m *Message) Decrypt(alg jwa.KeyEncryptionAlgorithm, key interface{}) ([]byte, error) {
	var err error

	if len(m.Recipients) == 0 {
		return nil, errors.New("no recipients, can not proceed with decrypt")
	}

	enc := m.ProtectedHeader.ContentEncryption

	h := NewHeader()
	if err := h.Copy(m.ProtectedHeader.Header); err != nil {
		return nil, errors.Wrap(err, `failed to copy protected headers`)
	}
	h, err = h.Merge(m.UnprotectedHeader)
	if err != nil {
		if debug.Enabled {
			debug.Printf("failed to merge unprotected header")
		}
		return nil, errors.Wrap(err, "failed to merge headers for message decryption")
	}

	aad, err := m.AuthenticatedData.Base64Encode()
	if err != nil {
		return nil, errors.Wrap(err, "failed to base64 encode authenticated data for message decryption")
	}
	ciphertext := m.CipherText.Bytes()
	iv := m.InitializationVector.Bytes()
	tag := m.Tag.Bytes()

	cipher, err := buildContentCipher(enc)
	if err != nil {
		return nil, errors.Wrap(err, "unsupported content cipher algorithm '"+enc.String()+"'")
	}
	keysize := cipher.KeySize()

	var plaintext []byte
	for _, recipient := range m.Recipients {
		if debug.Enabled {
			debug.Printf("Attempting to check if we can decode for recipient (alg = %s)", recipient.Header.Algorithm)
		}
		if recipient.Header.Algorithm != alg {
			continue
		}

		h2 := NewHeader()
		if err := h2.Copy(h); err != nil {
			if debug.Enabled {
				debug.Printf("failed to copy header: %s", err)
			}
			continue
		}

		h2, err := h2.Merge(recipient.Header)
		if err != nil {
			if debug.Enabled {
				debug.Printf("Failed to merge! %s", err)
			}
			continue
		}

		k, err := BuildKeyDecrypter(h2.Algorithm, h2, key, keysize)
		if err != nil {
			if debug.Enabled {
				debug.Printf("failed to create key decrypter: %s", err)
			}
			continue
		}

		cek, err := k.KeyDecrypt(recipient.EncryptedKey.Bytes())
		if err != nil {
			if debug.Enabled {
				debug.Printf("failed to decrypt key: %s", err)
			}
			continue
		}

		plaintext, err = cipher.decrypt(cek, iv, ciphertext, tag, aad)
		if err == nil {
			break
		}
		if debug.Enabled {
			debug.Printf("DecryptMessage: failed to decrypt using %s: %s", h2.Algorithm, err)
		}
		// Keep looping because there might be another key with the same algo
	}

	if plaintext == nil {
		return nil, errors.New("failed to find matching recipient to decrypt key")
	}

	if h.Compression == jwa.Deflate {
		output := bytes.Buffer{}
		w, _ := flate.NewWriter(&output, 1)
		in := plaintext
		for len(in) > 0 {
			n, err := w.Write(in)
			if err != nil {
				return nil, errors.Wrap(err, `failed to write to compression writer`)
			}
			in = in[n:]
		}
		if err := w.Close(); err != nil {
			return nil, errors.Wrap(err, "failed to close compression writer")
		}
		plaintext = output.Bytes()
	}

	return plaintext, nil
}

func buildContentCipher(alg jwa.ContentEncryptionAlgorithm) (ContentCipher, error) {
	switch alg {
	case jwa.A128GCM, jwa.A192GCM, jwa.A256GCM, jwa.A128CBC_HS256, jwa.A192CBC_HS384, jwa.A256CBC_HS512:
		return NewAesContentCipher(alg)
	}

	return nil, ErrUnsupportedAlgorithm
}
