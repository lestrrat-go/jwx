package content_crypt

import (
	"github.com/lestrrat-go/jwx/internal/debug"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe/internal/cipher"
	"github.com/lestrrat-go/jwx/jwe/internal/keygen"
	"github.com/pkg/errors"
)

func (c Generic) Algorithm() jwa.ContentEncryptionAlgorithm {
	return c.alg
}

func (c Generic) Encrypt(cek, plaintext, aad []byte) ([]byte, []byte, []byte, error) {
	if debug.Enabled {
		debug.Printf("ContentCrypt.Encrypt: cek        = %x (%d)", cek, len(cek))
		debug.Printf("ContentCrypt.Encrypt: ciphertext = %x (%d)", plaintext, len(plaintext))
		debug.Printf("ContentCrypt.Encrypt: aad        = %x (%d)", aad, len(aad))
	}
	iv, encrypted, tag, err := c.cipher.Encrypt(cek, plaintext, aad)
	if err != nil {
		if debug.Enabled {
			debug.Printf("cipher.encrypt failed")
		}

		return nil, nil, nil, errors.Wrap(err, `failed to crypt content`)
	}

	return iv, encrypted, tag, nil
}

func (c Generic) Decrypt(cek, iv, ciphertext, tag, aad []byte) ([]byte, error) {
	return c.cipher.Decrypt(cek, iv, ciphertext, tag, aad)
}

func NewAES(alg jwa.ContentEncryptionAlgorithm) (*Generic, error) {
	if debug.Enabled {
		debug.Printf("AES Crypt: alg = %s", alg)
	}
	c, err := cipher.NewAES(alg)
	if err != nil {
		return nil, errors.Wrap(err, `aes crypt: failed to create content cipher`)
	}

	if debug.Enabled {
		debug.Printf("AES Crypt: cipher.keysize = %d", c.KeySize())
	}

	return &Generic{
		alg:     alg,
		cipher:  c,
		cekgen:  keygen.NewRandom(c.KeySize() * 2),
		keysize: c.KeySize() * 2,
		tagsize: 16,
	}, nil
}

func (c Generic) KeySize() int {
	return c.keysize
}
