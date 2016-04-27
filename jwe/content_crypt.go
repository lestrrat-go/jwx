package jwe

import (
	"github.com/lestrrat/go-jwx/internal/debug"
	"github.com/lestrrat/go-jwx/jwa"
	"github.com/pkg/errors"
)

func (c GenericContentCrypt) Algorithm() jwa.ContentEncryptionAlgorithm {
	return c.alg
}

func (c GenericContentCrypt) Encrypt(cek, plaintext, aad []byte) ([]byte, []byte, []byte, error) {
	if debug.Enabled {
		debug.Printf("ContentCrypt.Encrypt: cek        = %x (%d)", cek, len(cek))
		debug.Printf("ContentCrypt.Encrypt: ciphertext = %x (%d)", plaintext, len(plaintext))
		debug.Printf("ContentCrypt.Encrypt: aad        = %x (%d)", aad, len(aad))
	}
	iv, encrypted, tag, err := c.cipher.encrypt(cek, plaintext, aad)
	if err != nil {
		if debug.Enabled {
			debug.Printf("cipher.encrypt failed")
		}

		return nil, nil, nil, errors.Wrap(err, `failed to crypt content`)
	}

	return iv, encrypted, tag, nil
}

func (c GenericContentCrypt) Decrypt(cek, iv, ciphertext, tag, aad []byte) ([]byte, error) {
	return c.cipher.decrypt(cek, iv, ciphertext, tag, aad)
}

func NewAesCrypt(alg jwa.ContentEncryptionAlgorithm) (*GenericContentCrypt, error) {
	if debug.Enabled {
		debug.Printf("AES Crypt: alg = %s", alg)
	}
	cipher, err := NewAesContentCipher(alg)
	if err != nil {
		return nil, errors.Wrap(err, `aes crypt: failed to create content cipher`)
	}

	if debug.Enabled {
		debug.Printf("AES Crypt: cipher.keysize = %d", cipher.KeySize())
	}

	return &GenericContentCrypt{
		alg:     alg,
		cipher:  cipher,
		cekgen:  NewRandomKeyGenerate(cipher.KeySize() * 2),
		keysize: cipher.KeySize() * 2,
		tagsize: 16,
	}, nil
}

func (c GenericContentCrypt) KeySize() int {
	return c.keysize
}
