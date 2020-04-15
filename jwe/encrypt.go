package jwe

import (
	"context"

	"github.com/lestrrat-go/jwx/internal/debug"
	"github.com/lestrrat-go/jwx/jwe/internal/keyenc"
	"github.com/lestrrat-go/jwx/jwe/internal/keygen"
	"github.com/pkg/errors"
)

// NewMultiEncrypt creates a new Encrypt struct. The caller is responsible
// for instantiating valid inputs for ContentEncrypter, KeyGenerator,
// and keyenc.Encrypters.
func NewMultiEncrypt(cc ContentEncrypter, kg keygen.Generator, ke ...keyenc.Encrypter) *MultiEncrypt {
	e := &MultiEncrypt{
		ContentEncrypter: cc,
		generator:        kg,
		encrypters:       ke,
	}
	return e
}

// Encrypt takes the plaintext and encrypts into a JWE message.
func (e MultiEncrypt) Encrypt(plaintext []byte) (*Message, error) {
	bk, err := e.generator.Generate()
	if err != nil {
		if debug.Enabled {
			debug.Printf("Failed to generate key: %s", err)
		}
		return nil, errors.Wrap(err, "failed to generate key")
	}
	cek := bk.Bytes()

	if debug.Enabled {
		debug.Printf("Encrypt: generated cek len = %d", len(cek))
	}

	protected := NewHeaders()
	protected.Set(ContentEncryptionKey, e.ContentEncrypter.Algorithm())

	// In JWE, multiple recipients may exist -- they receive an
	// encrypted version of the CEK, using their key encryption
	// algorithm of choice.
	recipients := make([]Recipient, len(e.encrypters))
	for i, enc := range e.encrypters {
		r := NewRecipient()
		r.Headers.Set("alg", enc.Algorithm())
		if v := enc.KeyID(); v != "" {
			r.Headers.Set("kid", v)
		}
		enckey, err := enc.Encrypt(cek)
		if err != nil {
			if debug.Enabled {
				debug.Printf("Failed to encrypt key: %s", err)
			}
			return nil, errors.Wrap(err, `failed to encrypt key`)
		}
		r.EncryptedKey = enckey.Bytes()
		if hp, ok := enckey.(populater); ok {
			hp.Populate(r.Headers)
		}
		if debug.Enabled {
			debug.Printf("Encrypt: encrypted_key = %x (%d)", enckey.Bytes(), len(enckey.Bytes()))
		}
		recipients[i] = *r
	}

	// If there's only one recipient, you want to include that in the
	// protected header
	if len(recipients) == 1 {
		h, err := mergeHeaders(context.TODO(), protected, recipients[0].Headers)
		if err != nil {
			return nil, errors.Wrap(err, "failed to merge protected headers")
		}
		protected = h
	}

	aad, err := protected.Encode()
	if err != nil {
		return nil, errors.Wrap(err, "failed to base64 encode protected headers")
	}

	// ...on the other hand, there's only one content cipher.
	iv, ciphertext, tag, err := e.ContentEncrypter.Encrypt(cek, plaintext, aad)
	if err != nil {
		if debug.Enabled {
			debug.Printf("Failed to encrypt: %s", err)
		}
		return nil, errors.Wrap(err, "failed to encrypt payload")
	}

	if debug.Enabled {
		debug.Printf("Encrypt.Encrypt: cek        = %x (%d)", cek, len(cek))
		debug.Printf("Encrypt.Encrypt: aad        = %x", aad)
		debug.Printf("Encrypt.Encrypt: ciphertext = %x", ciphertext)
		debug.Printf("Encrypt.Encrypt: iv         = %x", iv)
		debug.Printf("Encrypt.Encrypt: tag        = %x", tag)
	}

	msg := NewMessage()
	msg.authenticatedData.Base64Decode(aad)
	msg.cipherText = ciphertext
	msg.initializationVector = iv
	msg.protectedHeaders = protected
	msg.recipients = recipients
	msg.tag = tag

	return msg, nil
}
