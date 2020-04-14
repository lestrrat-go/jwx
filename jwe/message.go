package jwe

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/json"

	"github.com/lestrrat-go/jwx/buffer"
	"github.com/lestrrat-go/jwx/internal/debug"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/pkg/errors"
)

// NewRecipient creates a Recipient object
func NewRecipient() *Recipient {
	return &Recipient{
		Headers: NewHeaders(),
	}
}

// NewEncodedHeader creates a new encoded Header object
func NewEncodedHeader() *EncodedHeader {
	return &EncodedHeader{
		Headers: NewHeaders(),
	}
}

func mergeHeaders(ctx context.Context, h1, h2 Headers) (Headers, error) {
	h3 := NewHeaders()

	if h1 != nil {
		for iter := h1.Iterate(ctx); iter.Next(ctx); {
			pair := iter.Pair()
			h3.Set(pair.Key.(string), pair.Value)
		}
	}

	if h2 != nil {
		for iter := h2.Iterate(ctx); iter.Next(ctx); {
			pair := iter.Pair()
			h3.Set(pair.Key.(string), pair.Value)
		}
	}

	return h3, nil
}

func mergeMarshal(e interface{}, p map[string]interface{}) ([]byte, error) {
	buf, err := json.Marshal(e)
	if err != nil {
		return nil, errors.Wrap(err, `failed to marshal e`)
	}

	if len(p) == 0 {
		return buf, nil
	}

	ext, err := json.Marshal(p)
	if err != nil {
		return nil, errors.Wrap(err, `failed to marshal p`)
	}

	if len(buf) < 2 {
		return nil, errors.New(`invalid json`)
	}

	if buf[0] != '{' || buf[len(buf)-1] != '}' {
		return nil, errors.New("invalid JSON")
	}
	buf[len(buf)-1] = ','
	buf = append(buf, ext[1:]...)
	return buf, nil
}

// Base64Encode creates the base64 encoded version of the JSON
// representation of this header
func (e EncodedHeader) Base64Encode() ([]byte, error) {
	buf, err := json.Marshal(e.Headers)
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

	if err := json.Unmarshal(b.Bytes(), e.Headers); err != nil {
		return errors.Wrap(err, "failed to unmarshal buffer")
	}

	return nil
}

// NewMessage creates a new message
func NewMessage() *Message {
	return &Message{
		ProtectedHeader:   NewEncodedHeader(),
		UnprotectedHeader: NewHeaders(),
	}
}

// Decrypt decrypts the message using the specified algorithm and key
func (m *Message) Decrypt(alg jwa.KeyEncryptionAlgorithm, key interface{}) ([]byte, error) {
	var err error

	if len(m.Recipients) == 0 {
		return nil, errors.New("no recipients, can not proceed with decrypt")
	}

	enc := m.ProtectedHeader.ContentEncryption()

	h, err := mergeHeaders(context.TODO(), nil, m.ProtectedHeader.Headers)
	if err != nil {
		return nil, errors.Wrap(err, `failed to copy protected headers`)
	}
	h, err = mergeHeaders(context.TODO(), h, m.UnprotectedHeader)
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
			debug.Printf("Attempting to check if we can decode for recipient (alg = %s)", recipient.Headers.Algorithm)
		}
		if recipient.Headers.Algorithm() != alg {
			continue
		}

		h2, err := mergeHeaders(context.TODO(), nil, h)
		if err != nil {
			if debug.Enabled {
				debug.Printf("failed to copy header: %s", err)
			}
			continue
		}

		h2, err = mergeHeaders(context.TODO(), h2, recipient.Headers)
		if err != nil {
			if debug.Enabled {
				debug.Printf("Failed to merge! %s", err)
			}
			continue
		}

		k, err := BuildKeyDecrypter(h2.Algorithm(), h2, key, keysize)
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

	if h.Compression() == jwa.Deflate {
		var output bytes.Buffer
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
