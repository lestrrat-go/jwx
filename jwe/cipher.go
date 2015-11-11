package jwe

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jwe/aescbc"
)

const (
	TagSize = 16
)

func (f AeadFetchFunc) AeadFetch(key []byte) (cipher.AEAD, error) {
	return f(key)
}

var GcmAeadFetch = AeadFetchFunc(func(key []byte) (cipher.AEAD, error) {
	aescipher, err := aes.NewCipher(key)
	if err != nil {
		debug("GcmAeadFetch: failed to create cipher")
		return nil, err
	}

	return cipher.NewGCM(aescipher)
})
var CbcAeadFetch = AeadFetchFunc(func(key []byte) (cipher.AEAD, error) {
	aead, err := aescbc.New(key, aes.NewCipher)
	if err != nil {
		debug("CbcAeadFetch: failed to create aead fetcher")
		return nil, err
	}
	return aead, nil
})

func (c AesContentCipher) KeySize() int {
	return c.keysize
}

func (c AesContentCipher) TagSize() int {
	return c.tagsize
}

func NewAesContentCipher(alg jwa.ContentEncryptionAlgorithm) (*AesContentCipher, error) {
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

	return &AesContentCipher{
		keysize:     keysize,
		tagsize:     TagSize,
		AeadFetcher: fetcher,
	}, nil
}

func (c AesContentCipher) encrypt(cek, plaintext, aad []byte) (iv, ciphertext, tag []byte, err error) {
	var aead cipher.AEAD
	aead, err = c.AeadFetch(cek)
	if err != nil {
		debug("AeadFetch failed")
		return
	}

	// Seal may panic (argh!), so protect ourselves from that
	defer func() {
		if e := recover(); e != nil {
			switch e.(type) {
			case error:
				err = e.(error)
			case string:
				err = errors.New(e.(string))
			default:
				err = fmt.Errorf("%s", e)
			}
			return
		}
	}()

	if c.NonceGenerator == nil {
		iv, err = NewRandomKeyGenerate(aead.NonceSize()).KeyGenerate()
	} else {
		iv, err = c.NonceGenerator.KeyGenerate()
	}
	if err != nil {
		return
	}

	ciphertext = aead.Seal(nil, iv, plaintext, aad)
	tagoffset := len(ciphertext) - c.TagSize()
	tag = ciphertext[tagoffset:]
	ciphertext = ciphertext[:tagoffset]

	return
}

func (c AesContentCipher) decrypt(cek, iv, ciphertxt, tag, aad []byte) (plaintext []byte, err error) {
	aead, err := c.AeadFetch(cek)
	if err != nil {
		debug("AeadFetch failed for %v", cek)
		return nil, err
	}

	// Open may panic (argh!), so protect ourselves from that
	defer func() {
		if e := recover(); e != nil {
			switch e.(type) {
			case error:
				err = e.(error)
			case string:
				err = errors.New(e.(string))
			default:
				err = fmt.Errorf("%s", e)
			}
			return
		}
	}()

	combined := make([]byte, len(ciphertxt)+len(tag))
	copy(combined, ciphertxt)
	copy(combined[len(ciphertxt):], tag)
	plaintext, err = aead.Open(nil, iv, combined, aad)
	return
}

func NewRsaContentCipher(alg jwa.ContentEncryptionAlgorithm, pubkey *rsa.PublicKey) (*RsaContentCipher, error) {
	return &RsaContentCipher{
		pubkey: pubkey,
	}, nil
}
