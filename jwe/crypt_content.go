package jwe

import (
	"github.com/lestrrat/go-jwx/internal/debug"
	"github.com/lestrrat/go-jwx/jwa"
)

func (c GenericContentCrypt) Algorithm() jwa.ContentEncryptionAlgorithm {
	return c.alg
}

func (c GenericContentCrypt) Encrypt(cek, plaintext, aad []byte) ([]byte, []byte, []byte, error) {
	debug.Printf("ContentCrypt.Encrypt: cek        = %x", cek)
	debug.Printf("ContentCrypt.Encrypt: ciphertext = %x", plaintext)
	debug.Printf("ContentCrypt.Encrypt: aad        = %x", aad)
	iv, encrypted, tag, err := c.cipher.encrypt(cek, plaintext, aad)
	if err != nil {
		debug.Printf("cipher.encrypt failed")
		return nil, nil, nil, err
	}

	return iv, encrypted, tag, nil
}

func (c GenericContentCrypt) Decrypt(cek, iv, ciphertext, tag, aad []byte) ([]byte, error) {
	return c.cipher.decrypt(cek, iv, ciphertext, tag, aad)
}

func NewAesCrypt(alg jwa.ContentEncryptionAlgorithm) (*GenericContentCrypt, error) {
	cipher, err := NewAesContentCipher(alg)
	if err != nil {
		return nil, err
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
