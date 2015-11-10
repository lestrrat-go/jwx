package jwe

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jwe/aescbc"
)

const (
	TagSize = 16
)

type AeadFetcher interface {
	AeadFetch([]byte) (cipher.AEAD, error)
}

type AeadFetchFunc func([]byte) (cipher.AEAD, error)

func (f AeadFetchFunc) AeadFetch(key []byte) (cipher.AEAD, error) {
	return f(key)
}

var GcmAeadFetch = AeadFetchFunc(func(key []byte) (cipher.AEAD, error) {
	aescipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(aescipher)
})
var CbcAeadFetch = AeadFetchFunc(func(key []byte) (cipher.AEAD, error) {
	return aescbc.New(key, aes.NewCipher)
})

type AesContentCipher struct {
	AeadFetcher
	keysize int
	tagsize int
}

func NewContentCipher(keysize int, f AeadFetcher) *AesContentCipher {
	return &AesContentCipher{
		keysize: keysize,
		tagsize: TagSize,
		AeadFetcher: f,
	}
}

func (c AesContentCipher) KeySize() int {
	return c.keysize
}

func (c AesContentCipher) TagSize() int {
	return c.tagsize
}

func BuildCipher(alg jwa.ContentEncryptionAlgorithm) (ContentCipher, error) {
	var keysize int
	var fetcher AeadFetcher
	switch alg {
	case jwa.A128GCM:
		keysize = 16
		fetcher = GcmAeadFetch
	case jwa.A192GCM:
		keysize = 24
		fetcher = GcmAeadFetch
	case jwa.A256GCM:
		keysize = 32
		fetcher = GcmAeadFetch
	case jwa.A128CBC_HS256:
		keysize = 16
		fetcher = CbcAeadFetch
	case jwa.A192CBC_HS384:
		keysize = 24
		fetcher = CbcAeadFetch
	case jwa.A256CBC_HS512:
		keysize = 32
		fetcher = CbcAeadFetch
	default:
		return nil, ErrUnsupportedAlgorithm
	}

	return NewContentCipher(keysize, fetcher), nil
}

func (c AesContentCipher) encrypt(cek, iv, plaintext, aad []byte) ([]byte, error) {
	aead, err := c.AeadFetch(cek)
	if err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, iv, plaintext, aad)
	return ciphertext, nil
}

func (c AesContentCipher) decrypt(cek, iv, ciphertxt, aad []byte) ([]byte, error) {
	aead, err := c.AeadFetch(cek)
	if err != nil {
		return nil, err
	}

	return aead.Open(nil, iv, ciphertxt, aad)
}
