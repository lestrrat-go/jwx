package content_crypt

import (
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe/internal/cipher"
	"github.com/lestrrat-go/pdebug"
	"github.com/pkg/errors"
)

func (c Generic) Algorithm() jwa.ContentEncryptionAlgorithm {
	return c.alg
}

func (c Generic) Encrypt(cek, plaintext, aad []byte) ([]byte, []byte, []byte, error) {
	if pdebug.Enabled {
		pdebug.Printf("ContentCrypt.Encrypt: cek        = %x (%d)", cek, len(cek))
		pdebug.Printf("ContentCrypt.Encrypt: plaintext  = %x (%d)", plaintext, len(plaintext))
		pdebug.Printf("ContentCrypt.Encrypt: aad        = %x (%d)", aad, len(aad))
	}
	iv, encrypted, tag, err := c.cipher.Encrypt(cek, plaintext, aad)
	if err != nil {
		if pdebug.Enabled {
			pdebug.Printf("cipher.encrypt failed")
		}

		return nil, nil, nil, errors.Wrap(err, `failed to crypt content`)
	}

	return iv, encrypted, tag, nil
}

func (c Generic) Decrypt(cek, iv, ciphertext, tag, aad []byte) ([]byte, error) {
	return c.cipher.Decrypt(cek, iv, ciphertext, tag, aad)
}

func NewGeneric(alg jwa.ContentEncryptionAlgorithm) (*Generic, error) {
	if pdebug.Enabled {
		g := pdebug.Marker("NewAES (alg = %s)", alg)
		defer g.End()
	}

	c, err := cipher.NewAES(alg)
	if err != nil {
		return nil, errors.Wrap(err, `aes crypt: failed to create content cipher`)
	}

	if pdebug.Enabled {
		pdebug.Printf("AES Crypt: cipher.keysize = %d", c.KeySize())
	}

	keysize := c.KeySize()
	switch alg {
	case jwa.A128GCM, jwa.A192GCM, jwa.A256GCM:
	case jwa.A128CBC_HS256, jwa.A192CBC_HS384, jwa.A256CBC_HS512:
		keysize = keysize * 2
	}
	return &Generic{
		alg:     alg,
		cipher:  c,
		keysize: keysize,
		tagsize: 16,
	}, nil
}

func (c Generic) KeySize() int {
	return c.keysize
}
