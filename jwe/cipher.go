package jwe

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/lestrrat/go-jwx/internal/debug"
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
		debug.Printf("GcmAeadFetch: failed to create cipher")
		return nil, fmt.Errorf("cipher: failed to create AES cipher for GCM: %s", err)
	}

	return cipher.NewGCM(aescipher)
})
var CbcAeadFetch = AeadFetchFunc(func(key []byte) (cipher.AEAD, error) {
	aead, err := aescbc.New(key, aes.NewCipher)
	if err != nil {
		debug.Printf("CbcAeadFetch: failed to create aead fetcher (%v): %s", key, err)
		return nil, fmt.Errorf("cipher: failed to create AES cipher for CBC: %s", err)
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
		keysize = 16 * 2
		fetcher = CbcAeadFetch
	case jwa.A192CBC_HS384:
		keysize = 24 * 2
		fetcher = CbcAeadFetch
	case jwa.A256CBC_HS512:
		keysize = 32 * 2
		fetcher = CbcAeadFetch
	default:
		return nil, fmt.Errorf(
			"failed to create AES content cipher: %s",
			ErrUnsupportedAlgorithm,
		)
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
		debug.Printf("AeadFetch failed: %s", err)
		err = fmt.Errorf("failed to fetch AEAD: %s", err)
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

	var bs ByteSource
	if c.NonceGenerator == nil {
		bs, err = NewRandomKeyGenerate(aead.NonceSize()).KeyGenerate()
	} else {
		bs, err = c.NonceGenerator.KeyGenerate()
	}
	if err != nil {
		return
	}
	iv = bs.Bytes()

	combined := aead.Seal(nil, iv, plaintext, aad)
	tagoffset := len(combined) - c.TagSize()
	debug.Printf("tagsize = %d", c.TagSize())
	tag = combined[tagoffset:]
	ciphertext = make([]byte, tagoffset)
	copy(ciphertext, combined[:tagoffset])

	debug.Printf("encrypt: combined   = %x (%d)\n", combined, len(combined))
	debug.Printf("encrypt: ciphertext = %x (%d)\n", ciphertext, len(ciphertext))
	debug.Printf("encrypt: tag        = %x (%d)\n", tag, len(tag))
	debug.Printf("finally ciphertext = %x\n", ciphertext)

	return
}

func (c AesContentCipher) decrypt(cek, iv, ciphertxt, tag, aad []byte) (plaintext []byte, err error) {
	aead, err := c.AeadFetch(cek)
	if err != nil {
		debug.Printf("AeadFetch failed for %v: %s", cek, err)
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

	debug.Printf("AesContentCipher.decrypt: combined = %x (%d)", combined, len(combined))

	plaintext, err = aead.Open(nil, iv, combined, aad)
	return
}

func NewRsaContentCipher(alg jwa.ContentEncryptionAlgorithm, pubkey *rsa.PublicKey) (*RsaContentCipher, error) {
	return &RsaContentCipher{
		pubkey: pubkey,
	}, nil
}
