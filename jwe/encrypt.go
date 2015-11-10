package jwe

import (
	"crypto"
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"io"

	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jwe/aescbc"
	"github.com/lestrrat/go-jwx/jwe/keywrap"
)

// TODO GCM family
type KeyWrapEncrypt int

const (
	AESKeyWrap KeyWrapEncrypt = iota + 1
)

func (kw KeyWrapEncrypt) KeyEncrypt(cek, sharedKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(sharedKey)
	if err != nil {
		println("newcipher failed")
		return nil, err
	}
	encrypted, err := keywrap.Wrap(block, cek)
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}

func (m *MultiEncrypt) MultiEncrypt(payload []byte, aad []byte) (*Message, error) {
	msg := NewMessage()
	msg.AuthenticatedData = aad
	msg.Protected = *NewHeader()
	msg.Protected.ContentEncryption = m.ContentEncryption
	/*
		for _, encrypt := range m.Encrypters {
			parts := encrypt.Encrypt(payload)
		}
	*/
	return nil, nil
}

type KeyDecoder interface {
	KeyDecode([]byte) ([]byte, error)
}

type RsaOaepKeyDecode struct {
	Algorithm  jwa.KeyEncryptionAlgorithm
	PrivateKey *rsa.PrivateKey
}

func (e RsaOaepKeyDecode) hash() (crypto.Hash, error) {
	var hash crypto.Hash
	switch e.Algorithm {
	case jwa.RSA_OAEP:
		hash = crypto.SHA1
	case jwa.RSA_OAEP_256:
		hash = crypto.SHA256
	default:
		return 0, ErrUnsupportedAlgorithm
	}
	return hash, nil
}

func (e RsaOaepKeyDecode) KeyDecode(payload []byte) ([]byte, error) {
	privkey := e.PrivateKey
	if privkey == nil {
		return nil, ErrMissingPrivateKey
	}

	hash, err := e.hash()
	if err != nil {
		return nil, err
	}
	_ = hash

	return nil, nil
	//	h := hash.New()
	//	return rsa.DecryptOAEP(h, rand.Reader, privkey, payload)
}

type Decrypter interface {
	Decrypter()
}

type CbcHmacDecrypt struct {
	Algorithm jwa.ContentEncryptionAlgorithm
}

type DirectDecrypt struct {
	Key []byte
}

func (d DirectDecrypt) Decrypt() ([]byte, error) {
	cek := make([]byte, len(d.Key))
	copy(cek, d.Key)
	return cek, nil
}

type AesKeyWrapDecrypt struct {
	Key []byte
}

func (d AesKeyWrapDecrypt) Decrypt(enckey []byte) ([]byte, error) {
	block, err := aes.NewCipher(d.Key)
	if err != nil {
		return nil, err
	}

	cek, err := keywrap.Unwrap(block, enckey)
	if err != nil {
		return nil, err
	}
	return cek, nil
}

func (d CbcHmacDecrypt) hash() (crypto.Hash, error) {
	var hash crypto.Hash
	switch d.Algorithm {
	case jwa.A128CBC_HS256:
		hash = crypto.SHA256
	case jwa.A192CBC_HS384:
		hash = crypto.SHA384
	case jwa.A256CBC_HS512:
		hash = crypto.SHA512
	default:
		return 0, ErrUnsupportedAlgorithm
	}

	return hash, nil
}

func (d CbcHmacDecrypt) Decrypt(key, hdr, iv, ciphertxt, payload []byte) ([]byte, error) {
	hash, err := d.hash()
	if err != nil {
		return nil, err
	}

	keysiz := hash.Size() / 2
	ek := key[keysiz:]
	mk := key[:keysiz]

	h := hmac.New(hash.New, mk)
	h.Write(hdr)
	h.Write(iv)
	h.Write(ciphertxt)
	h.Write(ek)
	return nil, nil
}

type KeyGenerator interface {
	KeySize() int
	KeyGenerate() ([]byte, error)
}

type ContentCipher interface {
	KeySize() int
	encrypt(cek, iv, aad, plaintext []byte) ([]byte, error)
	decrypt(cek, iv, aad, ciphertext []byte) ([]byte, error)
}

type KeyEncrypter interface {
	KeyEncrypt([]byte, []byte) ([]byte, error)
}

type Crypt struct {
	jwa.ContentEncryptionAlgorithm
	jwa.KeyEncryptionAlgorithm
	jwa.CompressionAlgorithm
	keyenc KeyEncrypter
	cipher ContentCipher
	cekgen KeyGenerator
	ivgen  KeyGenerator
}

func (c Crypt) Encrypt(plaintext, aad []byte) ([]byte, []byte, []byte, error) {
	cek, err := c.cekgen.KeyGenerate()
	if err != nil {
		return nil, nil, nil, err
	}

	iv, err := c.ivgen.KeyGenerate()
	if err != nil {
		return nil, nil, nil, err
	}

	encrypted, err := c.cipher.encrypt(cek, iv, plaintext, aad)
	if err != nil {
		return nil, nil, nil, err
	}

	return cek, iv, encrypted, nil
}

func (c Crypt) Decrypt(cek, iv, ciphertext, aad []byte) ([]byte, error) {
	return c.cipher.decrypt(cek, iv, ciphertext, aad)
}

type StaticKeyGenerate []byte

func (g StaticKeyGenerate) KeySize() int {
	return len(g)
}

func (g StaticKeyGenerate) KeyGenerate() ([]byte, error) {
	buf := make([]byte, g.KeySize())
	copy(buf, g)
	return buf, nil
}

type RandomKeyGenerate struct {
	keysize int
}

func NewRandomKeyGenerate(n int) RandomKeyGenerate {
	return RandomKeyGenerate{keysize: n}
}
func (g RandomKeyGenerate) KeySize() int {
	return g.keysize
}
func (g RandomKeyGenerate) KeyGenerate() ([]byte, error) {
	buf := make([]byte, g.keysize)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

type CbcHmacCipher struct {
	keysize int
}

func (c CbcHmacCipher) KeySize() int {
	return c.keysize // DUMMY
}

// returns the cipher text or an error
func (c CbcHmacCipher) encrypt(cek, iv, plaintext, aad []byte) ([]byte, error) {
	aead, err := aescbc.New(cek, aes.NewCipher)
	if err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, iv, plaintext, aad)
	return ciphertext, nil
}

func (c CbcHmacCipher) decrypt(cek, iv, ciphertxt, aad []byte) ([]byte, error) {
	aead, err := aescbc.New(cek, aes.NewCipher)
	if err != nil {
		return nil, err
	}

	return aead.Open(nil, iv, ciphertxt, aad)
}
