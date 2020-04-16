package jwe

import (
	"context"
	"sync"

	"github.com/lestrrat-go/jwx/internal/debug"
	"github.com/pkg/errors"
)

var encryptCtxPool = sync.Pool{
	New: func() interface{} {
		return &encryptCtx{}
	},
}

func getEncryptCtx() *encryptCtx {
	return encryptCtxPool.Get().(*encryptCtx)
}

func releaseEncryptCtx(ctx *encryptCtx) {
	ctx.contentEncrypter = nil
	ctx.generator = nil
	ctx.keyEncrypters = nil
	encryptCtxPool.Put(ctx)
}

// Encrypt takes the plaintext and encrypts into a JWE message.
func (e encryptCtx) Encrypt(plaintext []byte) (*Message, error) {
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
	protected.Set(ContentEncryptionKey, e.contentEncrypter.Algorithm())

	// In JWE, multiple recipients may exist -- they receive an
	// encrypted version of the CEK, using their key encryption
	// algorithm of choice.
	recipients := make([]Recipient, len(e.keyEncrypters))
	for i, enc := range e.keyEncrypters {
		r := NewRecipient()
		r.headers.Set("alg", enc.Algorithm())
		if v := enc.KeyID(); v != "" {
			r.headers.Set("kid", v)
		}
		enckey, err := enc.Encrypt(cek)
		if err != nil {
			if debug.Enabled {
				debug.Printf("Failed to encrypt key: %s", err)
			}
			return nil, errors.Wrap(err, `failed to encrypt key`)
		}
		r.encryptedKey = enckey.Bytes()
		if hp, ok := enckey.(populater); ok {
			hp.Populate(r.headers)
		}
		if debug.Enabled {
			debug.Printf("Encrypt: encrypted_key = %x (%d)", enckey.Bytes(), len(enckey.Bytes()))
		}
		recipients[i] = *r
	}

	// If there's only one recipient, you want to include that in the
	// protected header
	if len(recipients) == 1 {
		h, err := mergeHeaders(context.TODO(), protected, recipients[0].headers)
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
	iv, ciphertext, tag, err := e.contentEncrypter.Encrypt(cek, plaintext, aad)
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
