package jwe

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"fmt"

	"github.com/lestrrat-go/jwx/internal/json"
	"github.com/lestrrat-go/jwx/jwk"

	"github.com/lestrrat-go/jwx/buffer"
	"github.com/lestrrat-go/jwx/internal/base64"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/pdebug"
	"github.com/pkg/errors"
)

// NewRecipient creates a Recipient object
func NewRecipient() Recipient {
	return &stdRecipient{
		headers: NewHeaders(),
	}
}

func (r *stdRecipient) SetHeaders(h Headers) error {
	r.headers = h
	return nil
}

func (r *stdRecipient) SetEncryptedKey(v interface{}) error {
	return r.encryptedKey.Accept(v)
}

func (r *stdRecipient) Headers() Headers {
	return r.headers
}

func (r *stdRecipient) EncryptedKey() buffer.Buffer {
	return r.encryptedKey
}

type recipientMarshalProxy struct {
	Headers      Headers       `json:"header"`
	EncryptedKey buffer.Buffer `json:"encrypted_key"`
}

func (r *stdRecipient) UnmarshalJSON(buf []byte) error {
	var proxy recipientMarshalProxy
	proxy.Headers = NewHeaders()
	if err := json.Unmarshal(buf, &proxy); err != nil {
		return errors.Wrap(err, `failed to unmarshal json into recipient`)
	}

	r.headers = proxy.Headers
	r.encryptedKey = proxy.EncryptedKey
	return nil
}

func (r *stdRecipient) MarshalJSON() ([]byte, error) {
	var proxy recipientMarshalProxy
	proxy.Headers = r.headers
	proxy.EncryptedKey = r.encryptedKey

	return json.Marshal(proxy)
}

// NewMessage creates a new message
func NewMessage() *Message {
	return &Message{}
}

func (m *Message) AuthenticatedData() []byte {
	if m.authenticatedData == nil {
		return nil
	}
	return m.authenticatedData.Bytes()
}

func (m *Message) CipherText() []byte {
	if m.cipherText == nil {
		return nil
	}
	return m.cipherText.Bytes()
}

func (m *Message) InitializationVector() []byte {
	if m.initializationVector == nil {
		return nil
	}
	return m.initializationVector.Bytes()
}

func (m *Message) Tag() []byte {
	if m.tag == nil {
		return nil
	}
	return m.tag.Bytes()
}

func (m *Message) ProtectedHeaders() Headers {
	return m.protectedHeaders
}

func (m *Message) Recipients() []Recipient {
	return m.recipients
}

func (m *Message) UnprotectedHeaders() Headers {
	return m.unprotectedHeaders
}

const (
	AuthenticatedDataKey    = "aad"
	CipherTextKey           = "ciphertext"
	InitializationVectorKey = "iv"
	ProtectedHeadersKey     = "protected"
	RecipientsKey           = "recipients"
	TagKey                  = "tag"
	UnprotectedHeadersKey   = "unprotected"
	HeadersKey              = "header"
	EncryptedKeyKey         = "encrypted_key"
)

func (m *Message) Set(k string, v interface{}) error {
	switch k {
	case AuthenticatedDataKey:
		var acceptor buffer.Buffer
		if err := acceptor.Accept(v); err != nil {
			return errors.Wrapf(err, `invalid value %T for %s key`, v, AuthenticatedDataKey)
		}
		m.authenticatedData = &acceptor
	case CipherTextKey:
		var acceptor buffer.Buffer
		if err := acceptor.Accept(v); err != nil {
			return errors.Wrapf(err, `invalid value %T for %s key`, v, CipherTextKey)
		}
		m.cipherText = &acceptor
	case InitializationVectorKey:
		var acceptor buffer.Buffer
		if err := acceptor.Accept(v); err != nil {
			return errors.Wrapf(err, `invalid value %T for %s key`, v, InitializationVectorKey)
		}
		m.initializationVector = &acceptor
	case ProtectedHeadersKey:
		cv, ok := v.(Headers)
		if !ok {
			return errors.Errorf(`invalid value %T for %s key`, v, ProtectedHeadersKey)
		}
		m.protectedHeaders = cv
	case RecipientsKey:
		cv, ok := v.([]Recipient)
		if !ok {
			return errors.Errorf(`invalid value %T for %s key`, v, RecipientsKey)
		}
		m.recipients = cv
	case TagKey:
		var acceptor buffer.Buffer
		if err := acceptor.Accept(v); err != nil {
			return errors.Wrapf(err, `invalid value %T for %s key`, v, TagKey)
		}
		m.tag = &acceptor
	case UnprotectedHeadersKey:
		cv, ok := v.(Headers)
		if !ok {
			return errors.Errorf(`invalid value %T for %s key`, v, UnprotectedHeadersKey)
		}
		m.unprotectedHeaders = cv
	default:
		if m.unprotectedHeaders == nil {
			m.unprotectedHeaders = NewHeaders()
		}
		return m.unprotectedHeaders.Set(k, v)
	}
	return nil
}

type messageMarshalProxy struct {
	AuthenticatedData    *buffer.Buffer    `json:"aad,omitempty"`
	CipherText           *buffer.Buffer    `json:"ciphertext"`
	InitializationVector *buffer.Buffer    `json:"iv,omitempty"`
	ProtectedHeaders     json.RawMessage   `json:"protected"`
	Recipients           []json.RawMessage `json:"recipients,omitempty"`
	Tag                  *buffer.Buffer    `json:"tag,omitempty"`
	UnprotectedHeaders   Headers           `json:"unprotected,omitempty"`

	// For flattened structure. Headers is NOT a Headers type,
	// so that we can detect its presence by checking proxy.Headers != nil
	Headers      json.RawMessage `json:"header,omitempty"`
	EncryptedKey buffer.Buffer   `json:"encrypted_key,omitempty"`
}

func (m *Message) MarshalJSON() ([]byte, error) {
	// This is slightly convoluted, but we need to encode the
	// protected headers, so we do it by hand
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	fmt.Fprintf(&buf, `{`)

	var wrote bool
	if aad := m.AuthenticatedData(); len(aad) > 0 {
		wrote = true
		fmt.Fprintf(&buf, `%#v:`, AuthenticatedDataKey)
		if err := enc.Encode(base64.EncodeToString(aad)); err != nil {
			return nil, errors.Wrapf(err, `failed to encode %s field`, AuthenticatedDataKey)
		}
	}
	if cipherText := m.CipherText(); len(cipherText) > 0 {
		if wrote {
			fmt.Fprintf(&buf, `,`)
		}
		wrote = true
		fmt.Fprintf(&buf, `%#v:`, CipherTextKey)
		if err := enc.Encode(base64.EncodeToString(cipherText)); err != nil {
			return nil, errors.Wrapf(err, `failed to encode %s field`, CipherTextKey)
		}
	}

	if iv := m.InitializationVector(); len(iv) > 0 {
		if wrote {
			fmt.Fprintf(&buf, `,`)
		}
		wrote = true
		fmt.Fprintf(&buf, `%#v:`, InitializationVectorKey)
		if err := enc.Encode(base64.EncodeToString(iv)); err != nil {
			return nil, errors.Wrapf(err, `failed to encode %s field`, InitializationVectorKey)
		}
	}

	if h := m.ProtectedHeaders(); h != nil {
		encodedHeaders, err := h.Encode()
		if err != nil {
			return nil, errors.Wrap(err, `failed to encode protected headers`)
		}

		if len(encodedHeaders) > 2 {
			if wrote {
				fmt.Fprintf(&buf, `,`)
			}
			wrote = true
			fmt.Fprintf(&buf, `%#v:%#v`, ProtectedHeadersKey, string(encodedHeaders))
		}
	}

	if recipients := m.Recipients(); len(recipients) > 0 {
		if wrote {
			fmt.Fprintf(&buf, `,`)
		}
		if len(recipients) == 1 { // Use flattened format
			fmt.Fprintf(&buf, `%#v:`, HeadersKey)
			if err := enc.Encode(recipients[0].Headers()); err != nil {
				return nil, errors.Wrapf(err, `failed to encode %s field`, HeadersKey)
			}
			if ek := recipients[0].EncryptedKey(); ek.Len() > 0 {
				fmt.Fprintf(&buf, `,%#v:`, EncryptedKeyKey)
				if err := enc.Encode(ek); err != nil {
					return nil, errors.Wrapf(err, `failed to encode %s field`, EncryptedKeyKey)
				}
			}
		} else {
			fmt.Fprintf(&buf, `%#v:`, RecipientsKey)
			if err := enc.Encode(recipients); err != nil {
				return nil, errors.Wrapf(err, `failed to encode %s field`, RecipientsKey)
			}
		}
	}

	if tag := m.Tag(); len(tag) > 0 {
		if wrote {
			fmt.Fprintf(&buf, `,`)
		}
		fmt.Fprintf(&buf, `%#v:`, TagKey)
		if err := enc.Encode(base64.EncodeToString(tag)); err != nil {
			return nil, errors.Wrapf(err, `failed to encode %s field`, TagKey)
		}
	}

	if h := m.UnprotectedHeaders(); h != nil {
		unprotected, err := json.Marshal(h)
		if err != nil {
			return nil, errors.Wrap(err, `failed to encode unprotected headers`)
		}

		if len(unprotected) > 2 {
			fmt.Fprintf(&buf, `,%#v:%#v`, UnprotectedHeadersKey, string(unprotected))
		}
	}
	fmt.Fprintf(&buf, `}`)

	return buf.Bytes(), nil
}

func (m *Message) UnmarshalJSON(buf []byte) error {
	var proxy messageMarshalProxy
	proxy.UnprotectedHeaders = NewHeaders()

	if err := json.Unmarshal(buf, &proxy); err != nil {
		return errors.Wrap(err, `failed to unmashal JSON into message`)
	}

	var phstr string
	if err := json.Unmarshal(proxy.ProtectedHeaders, &phstr); err != nil {
		return errors.Wrap(err, `failed to unmarshal protected headers into string`)
	}

	h := NewHeaders()
	if err := h.Decode([]byte(phstr)); err != nil {
		return errors.Wrap(err, `failed to decode protected headers`)
	}

	// if this were a flattened message, we would see a "header" and "ciphertext"
	// field. TODO: do both of these conditions need to meet, or just one?
	if proxy.Headers != nil || len(proxy.EncryptedKey) > 0 {
		recipient := NewRecipient()
		hdrs := NewHeaders()
		if err := json.Unmarshal(proxy.Headers, hdrs); err != nil {
			return errors.Wrap(err, `failed to decode headers field`)
		}

		if err := recipient.SetHeaders(hdrs); err != nil {
			return errors.Wrap(err, `failed to set new headers`)
		}

		if err := recipient.SetEncryptedKey(proxy.EncryptedKey); err != nil {
			return errors.Wrap(err, `failed to set encryption key`)
		}

		m.recipients = append(m.recipients, recipient)
	} else {
		for i, recipientbuf := range proxy.Recipients {
			recipient := NewRecipient()
			if err := json.Unmarshal(recipientbuf, recipient); err != nil {
				return errors.Wrapf(err, `failed to decode recipient at index %d`, i)
			}

			m.recipients = append(m.recipients, recipient)
		}
	}

	m.authenticatedData = proxy.AuthenticatedData
	m.cipherText = proxy.CipherText
	m.initializationVector = proxy.InitializationVector
	m.protectedHeaders = h
	m.tag = proxy.Tag
	if !proxy.UnprotectedHeaders.(isZeroer).isZero() {
		m.unprotectedHeaders = proxy.UnprotectedHeaders
	}

	return nil
}

// Decrypt decrypts the message using the specified algorithm and key
func (m *Message) Decrypt(alg jwa.KeyEncryptionAlgorithm, key interface{}) ([]byte, error) {
	if pdebug.Enabled {
		g := pdebug.Marker("Message.Decrypt (alg = %s, key typ = %T)", alg, key)
		defer g.End()
	}

	var err error

	if pdebug.Enabled {
		g := pdebug.Marker("message.Decrypt (alg = %s)", alg)
		defer g.End()
	}

	ctx := context.TODO()
	h, err := m.protectedHeaders.Clone(ctx)
	if err != nil {
		return nil, errors.Wrap(err, `failed to copy protected headers`)
	}
	h, err = h.Merge(ctx, m.unprotectedHeaders)
	if err != nil {
		if pdebug.Enabled {
			pdebug.Printf("failed to merge unprotected header")
		}
		return nil, errors.Wrap(err, "failed to merge headers for message decryption")
	}

	enc := m.protectedHeaders.ContentEncryption()
	var aad []byte
	if aadContainer := m.authenticatedData; aadContainer != nil {
		aad, err = aadContainer.Base64Encode()
		if err != nil {
			return nil, errors.Wrap(err, "failed to base64 encode authenticated data for message decryption")
		}
	}

	computedAad, err := m.protectedHeaders.Encode()
	if err != nil {
		return nil, errors.Wrap(err, "failed to encode protected headers")
	}

	ciphertext := m.cipherText.Bytes()
	iv := m.initializationVector.Bytes()
	tag := m.tag.Bytes()

	dec := NewDecrypter(alg, enc, key).
		AuthenticatedData(aad).
		ComputedAuthenticatedData(computedAad).
		InitializationVector(iv).
		Tag(tag)

	var plaintext []byte
	var lastError error
	for _, recipient := range m.recipients {
		// strategy: try each recipient. If we fail in one of the steps,
		// keep looping because there might be another key with the same algo

		if pdebug.Enabled {
			pdebug.Printf("Attempting to check if we can decode for recipient (alg = %s)", recipient.Headers().Algorithm())
		}

		if recipient.Headers().Algorithm() != alg {
			// algorithms don't match
			continue
		}

		h2, err := h.Clone(ctx)
		if err != nil {
			lastError = errors.Wrap(err, `failed to copy headers (1)`)
			if pdebug.Enabled {
				pdebug.Printf(`%s`, lastError)
			}
			continue
		}

		h2, err = h2.Merge(ctx, recipient.Headers())
		if err != nil {
			lastError = errors.Wrap(err, `failed to copy headers (2)`)
			if pdebug.Enabled {
				pdebug.Printf(`%s`, lastError)
			}
			continue
		}

		switch alg {
		case jwa.ECDH_ES:
			// XXX for ECDH-ES
			// disable this entire case, and replace the next case statement with the following:
			//
			// ```START
			// case jwa.ECDH_ES, jwa.ECDH_ES_A128KW, jwa.ECDH_ES_A192KW, jwa.ECDH_ES_A256KW:
			// ```END
			return nil, errors.New(`ECDH-ES is not yet supported`)
		case jwa.ECDH_ES_A128KW, jwa.ECDH_ES_A192KW, jwa.ECDH_ES_A256KW:
			epkif, ok := h2.Get(EphemeralPublicKeyKey)
			if !ok {
				return nil, errors.New("failed to get 'epk' field")
			}
			epk, ok := epkif.(jwk.ECDSAPublicKey)
			if !ok {
				return nil, errors.Errorf("'epk' header is required as the key to build %s key decrypter", alg)
			}

			var pubkey ecdsa.PublicKey
			if err := epk.Raw(&pubkey); err != nil {
				return nil, errors.Wrap(err, "failed to get public key")
			}
			dec.PublicKey(&pubkey)

			if apu := h2.AgreementPartyUInfo(); apu.Len() > 0 {
				dec.AgreementPartyUInfo(apu.Bytes())
			}

			if apv := h2.AgreementPartyVInfo(); apv.Len() > 0 {
				dec.AgreementPartyVInfo(apv.Bytes())
			}
		}

		plaintext, err = dec.Decrypt(recipient.EncryptedKey().Bytes(), ciphertext)
		if err != nil {
			lastError = errors.Wrap(err, `failed to decrypt`)
			continue
		}

		if pdebug.Enabled {
			pdebug.Printf("Successfully decrypted message. Checking for compression...")
		}

		if h2.Compression() != jwa.Deflate {
			if pdebug.Enabled {
				pdebug.Printf("No compression handling necessary.")
			}
		} else {
			if pdebug.Enabled {
				pdebug.Printf("Uncompressing plaintext")
			}
			buf, err := uncompress(plaintext)
			if err != nil {
				lastError = errors.Wrap(err, `failed to uncompress payload`)
				if pdebug.Enabled {
					pdebug.Printf(`%s`, lastError)
				}
				continue
			}
			plaintext = buf
		}
		break
	}

	if plaintext == nil {
		if lastError != nil {
			return nil, errors.Errorf(`failed to find matching recipient to decrypt key (last error = %s)`, lastError)
		}
		return nil, errors.New("failed to find matching recipient")
	}

	return plaintext, nil
}
