package content_crypt //nolint:golint

import (
	"fmt"
	"sync"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe/internal/cipher"
)

var genericCache sync.Map // map[string]*Generic

func (c Generic) Algorithm() jwa.ContentEncryptionAlgorithm {
	return c.alg
}

func (c Generic) Encrypt(cek, plaintext, aad []byte) ([]byte, []byte, []byte, error) {
	iv, encrypted, tag, err := c.cipher.Encrypt(cek, plaintext, aad)
	if err != nil {
		return nil, nil, nil, fmt.Errorf(`failed to crypt content: %w`, err)
	}

	return iv, encrypted, tag, nil
}

func (c Generic) Decrypt(cek, iv, ciphertext, tag, aad []byte) ([]byte, error) {
	return c.cipher.Decrypt(cek, iv, ciphertext, tag, aad)
}

func NewGeneric(alg jwa.ContentEncryptionAlgorithm) (*Generic, error) {
	key := alg.String()
	if v, ok := genericCache.Load(key); ok {
		//nolint:forcetypeassert
		return v.(*Generic), nil
	}

	c, err := cipher.NewAES(key)
	if err != nil {
		return nil, fmt.Errorf(`aes crypt: failed to create content cipher: %w`, err)
	}

	g := &Generic{
		alg:     alg,
		cipher:  c,
		keysize: c.KeySize(),
		tagsize: 16,
	}
	genericCache.Store(key, g)
	return g, nil
}

func (c Generic) KeySize() int {
	return c.keysize
}
