package jwe

import (
	"context"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/internal/json"
	"github.com/lestrrat-go/jwx/v2/internal/pool"

	"github.com/lestrrat-go/jwx/v2/internal/base64"
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

func (r *stdRecipient) SetEncryptedKey(v []byte) error {
	r.encryptedKey = v
	return nil
}

func (r *stdRecipient) Headers() Headers {
	return r.headers
}

func (r *stdRecipient) EncryptedKey() []byte {
	return r.encryptedKey
}

type recipientMarshalProxy struct {
	Headers      Headers `json:"header"`
	EncryptedKey string  `json:"encrypted_key"`
}

func (r *stdRecipient) UnmarshalJSON(buf []byte) error {
	var proxy recipientMarshalProxy
	proxy.Headers = NewHeaders()
	if err := json.Unmarshal(buf, &proxy); err != nil {
		return errors.Wrap(err, `failed to unmarshal json into recipient`)
	}

	r.headers = proxy.Headers
	decoded, err := base64.DecodeString(proxy.EncryptedKey)
	if err != nil {
		return errors.Wrap(err, `failed to decode "encrypted_key"`)
	}
	r.encryptedKey = decoded
	return nil
}

func (r *stdRecipient) MarshalJSON() ([]byte, error) {
	buf := pool.GetBytesBuffer()
	defer pool.ReleaseBytesBuffer(buf)

	buf.WriteString(`{"header":`)
	hdrbuf, err := r.headers.MarshalJSON()
	if err != nil {
		return nil, errors.Wrap(err, `failed to marshal recipient header`)
	}
	buf.Write(hdrbuf)
	buf.WriteString(`,"encrypted_key":"`)
	buf.WriteString(base64.EncodeToString(r.encryptedKey))
	buf.WriteString(`"}`)

	ret := make([]byte, buf.Len())
	copy(ret, buf.Bytes())
	return ret, nil
}

// NewMessage creates a new message
func NewMessage() *Message {
	return &Message{}
}

func (m *Message) AuthenticatedData() []byte {
	return m.authenticatedData
}

func (m *Message) CipherText() []byte {
	return m.cipherText
}

func (m *Message) InitializationVector() []byte {
	return m.initializationVector
}

func (m *Message) Tag() []byte {
	return m.tag
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
	CountKey                = "p2c"
	InitializationVectorKey = "iv"
	ProtectedHeadersKey     = "protected"
	RecipientsKey           = "recipients"
	SaltKey                 = "p2s"
	TagKey                  = "tag"
	UnprotectedHeadersKey   = "unprotected"
	HeadersKey              = "header"
	EncryptedKeyKey         = "encrypted_key"
)

func (m *Message) Set(k string, v interface{}) error {
	switch k {
	case AuthenticatedDataKey:
		buf, ok := v.([]byte)
		if !ok {
			return errors.Errorf(`invalid value %T for %s key`, v, AuthenticatedDataKey)
		}
		m.authenticatedData = buf
	case CipherTextKey:
		buf, ok := v.([]byte)
		if !ok {
			return errors.Errorf(`invalid value %T for %s key`, v, CipherTextKey)
		}
		m.cipherText = buf
	case InitializationVectorKey:
		buf, ok := v.([]byte)
		if !ok {
			return errors.Errorf(`invalid value %T for %s key`, v, InitializationVectorKey)
		}
		m.initializationVector = buf
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
		buf, ok := v.([]byte)
		if !ok {
			return errors.Errorf(`invalid value %T for %s key`, v, TagKey)
		}
		m.tag = buf
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
	AuthenticatedData    string            `json:"aad,omitempty"`
	CipherText           string            `json:"ciphertext"`
	InitializationVector string            `json:"iv,omitempty"`
	ProtectedHeaders     json.RawMessage   `json:"protected"`
	Recipients           []json.RawMessage `json:"recipients,omitempty"`
	Tag                  string            `json:"tag,omitempty"`
	UnprotectedHeaders   Headers           `json:"unprotected,omitempty"`

	// For flattened structure. Headers is NOT a Headers type,
	// so that we can detect its presence by checking proxy.Headers != nil
	Headers      json.RawMessage `json:"header,omitempty"`
	EncryptedKey string          `json:"encrypted_key,omitempty"`
}

func (m *Message) MarshalJSON() ([]byte, error) {
	// This is slightly convoluted, but we need to encode the
	// protected headers, so we do it by hand
	buf := pool.GetBytesBuffer()
	defer pool.ReleaseBytesBuffer(buf)
	enc := json.NewEncoder(buf)
	fmt.Fprintf(buf, `{`)

	var wrote bool
	if aad := m.AuthenticatedData(); len(aad) > 0 {
		wrote = true
		fmt.Fprintf(buf, `%#v:`, AuthenticatedDataKey)
		if err := enc.Encode(base64.EncodeToString(aad)); err != nil {
			return nil, errors.Wrapf(err, `failed to encode %s field`, AuthenticatedDataKey)
		}
	}
	if cipherText := m.CipherText(); len(cipherText) > 0 {
		if wrote {
			fmt.Fprintf(buf, `,`)
		}
		wrote = true
		fmt.Fprintf(buf, `%#v:`, CipherTextKey)
		if err := enc.Encode(base64.EncodeToString(cipherText)); err != nil {
			return nil, errors.Wrapf(err, `failed to encode %s field`, CipherTextKey)
		}
	}

	if iv := m.InitializationVector(); len(iv) > 0 {
		if wrote {
			fmt.Fprintf(buf, `,`)
		}
		wrote = true
		fmt.Fprintf(buf, `%#v:`, InitializationVectorKey)
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
				fmt.Fprintf(buf, `,`)
			}
			wrote = true
			fmt.Fprintf(buf, `%#v:%#v`, ProtectedHeadersKey, string(encodedHeaders))
		}
	}

	if recipients := m.Recipients(); len(recipients) > 0 {
		if wrote {
			fmt.Fprintf(buf, `,`)
		}
		if len(recipients) == 1 { // Use flattened format
			fmt.Fprintf(buf, `%#v:`, HeadersKey)
			if err := enc.Encode(recipients[0].Headers()); err != nil {
				return nil, errors.Wrapf(err, `failed to encode %s field`, HeadersKey)
			}
			if ek := recipients[0].EncryptedKey(); len(ek) > 0 {
				fmt.Fprintf(buf, `,%#v:`, EncryptedKeyKey)
				if err := enc.Encode(base64.EncodeToString(ek)); err != nil {
					return nil, errors.Wrapf(err, `failed to encode %s field`, EncryptedKeyKey)
				}
			}
		} else {
			fmt.Fprintf(buf, `%#v:`, RecipientsKey)
			if err := enc.Encode(recipients); err != nil {
				return nil, errors.Wrapf(err, `failed to encode %s field`, RecipientsKey)
			}
		}
	}

	if tag := m.Tag(); len(tag) > 0 {
		if wrote {
			fmt.Fprintf(buf, `,`)
		}
		fmt.Fprintf(buf, `%#v:`, TagKey)
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
			fmt.Fprintf(buf, `,%#v:%#v`, UnprotectedHeadersKey, string(unprotected))
		}
	}
	fmt.Fprintf(buf, `}`)

	ret := make([]byte, buf.Len())
	copy(ret, buf.Bytes())
	return ret, nil
}

func (m *Message) UnmarshalJSON(buf []byte) error {
	var proxy messageMarshalProxy
	proxy.UnprotectedHeaders = NewHeaders()

	if err := json.Unmarshal(buf, &proxy); err != nil {
		return errors.Wrap(err, `failed to unmashal JSON into message`)
	}

	// Get the string value
	var protectedHeadersStr string
	if err := json.Unmarshal(proxy.ProtectedHeaders, &protectedHeadersStr); err != nil {
		return errors.Wrap(err, `failed to decode protected headers (1)`)
	}

	// It's now in _quoted_ base64 string. Decode it
	protectedHeadersRaw, err := base64.DecodeString(protectedHeadersStr)
	if err != nil {
		return errors.Wrap(err, "failed to base64 decoded protected headers buffer")
	}

	h := NewHeaders()
	if err := json.Unmarshal(protectedHeadersRaw, h); err != nil {
		return errors.Wrap(err, `failed to decode protected headers (2)`)
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

		if v := proxy.EncryptedKey; len(v) > 0 {
			buf, err := base64.DecodeString(v)
			if err != nil {
				return errors.Wrap(err, `failed to decode encrypted key`)
			}
			if err := recipient.SetEncryptedKey(buf); err != nil {
				return errors.Wrap(err, `failed to set encrypted key`)
			}
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

	if src := proxy.AuthenticatedData; len(src) > 0 {
		v, err := base64.DecodeString(src)
		if err != nil {
			return errors.Wrap(err, `failed to decode "aad"`)
		}
		m.authenticatedData = v
	}

	if src := proxy.CipherText; len(src) > 0 {
		v, err := base64.DecodeString(src)
		if err != nil {
			return errors.Wrap(err, `failed to decode "ciphertext"`)
		}
		m.cipherText = v
	}

	if src := proxy.InitializationVector; len(src) > 0 {
		v, err := base64.DecodeString(src)
		if err != nil {
			return errors.Wrap(err, `failed to decode "iv"`)
		}
		m.initializationVector = v
	}

	if src := proxy.Tag; len(src) > 0 {
		v, err := base64.DecodeString(src)
		if err != nil {
			return errors.Wrap(err, `failed to decode "tag"`)
		}
		m.tag = v
	}

	m.protectedHeaders = h
	if m.storeProtectedHeaders {
		// this is later used for decryption
		m.rawProtectedHeaders = base64.Encode(protectedHeadersRaw)
	}

	if !proxy.UnprotectedHeaders.(isZeroer).isZero() {
		m.unprotectedHeaders = proxy.UnprotectedHeaders
	}

	if len(m.recipients) == 0 {
		if err := m.makeDummyRecipient(proxy.EncryptedKey, m.protectedHeaders); err != nil {
			return errors.Wrap(err, `failed to setup recipient`)
		}
	}

	return nil
}

func (m *Message) makeDummyRecipient(enckeybuf string, protected Headers) error {
	// Recipients in this case should not contain the content encryption key,
	// so move that out
	hdrs, err := protected.Clone(context.TODO())
	if err != nil {
		return errors.Wrap(err, `failed to clone headers`)
	}

	if err := hdrs.Remove(ContentEncryptionKey); err != nil {
		return errors.Wrapf(err, "failed to remove %#v from public header", ContentEncryptionKey)
	}

	enckey, err := base64.DecodeString(enckeybuf)
	if err != nil {
		return errors.Wrap(err, `failed to decode encrypted key`)
	}

	if err := m.Set(RecipientsKey, []Recipient{
		&stdRecipient{
			headers:      hdrs,
			encryptedKey: enckey,
		},
	}); err != nil {
		return errors.Wrapf(err, `failed to set %s`, RecipientsKey)
	}
	return nil
}

func Compact(m *Message) ([]byte, error) {
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

	ctx := context.TODO()
	hcopy, err := m.protectedHeaders.Clone(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to copy protected header")
	}
	hcopy, err = hcopy.Merge(ctx, m.unprotectedHeaders)
	if err != nil {
		return nil, errors.Wrap(err, "failed to merge unprotected header")
	}
	hcopy, err = hcopy.Merge(ctx, recipient.Headers())
	if err != nil {
		return nil, errors.Wrap(err, "failed to merge recipient header")
	}

	protected, err := hcopy.Encode()
	if err != nil {
		return nil, errors.Wrap(err, "failed to encode header")
	}

	encryptedKey := base64.Encode(recipient.EncryptedKey())
	iv := base64.Encode(m.initializationVector)
	cipher := base64.Encode(m.cipherText)
	tag := base64.Encode(m.tag)

	buf := pool.GetBytesBuffer()
	defer pool.ReleaseBytesBuffer(buf)

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

	result := make([]byte, buf.Len())
	copy(result, buf.Bytes())
	return result, nil
}
