package jwe

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"hash"

	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jwe/keywrap"
)

func NewAesKeyWrap(alg jwa.KeyEncryptionAlgorithm, sharedkey []byte) (KeyWrapEncrypt, error) {
	return KeyWrapEncrypt{
		alg:       alg,
		sharedkey: sharedkey,
	}, nil
}

func (kw KeyWrapEncrypt) Algorithm() jwa.KeyEncryptionAlgorithm {
	return kw.alg
}

func (kw KeyWrapEncrypt) Kid() string {
	return kw.KeyID
}

func (kw KeyWrapEncrypt) KeyEncrypt(cek []byte) ([]byte, error) {
	block, err := aes.NewCipher(kw.sharedkey)
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

type RSAPKCS15KeyDecrypt struct {
	alg       jwa.KeyEncryptionAlgorithm
	privkey   *rsa.PrivateKey
	generator KeyGenerator
}

func NewRSAPKCS15KeyDecrypt(alg jwa.KeyEncryptionAlgorithm, privkey *rsa.PrivateKey, keysize int) *RSAPKCS15KeyDecrypt {
	generator := NewRandomKeyGenerate(keysize)
	return &RSAPKCS15KeyDecrypt{
		alg:       alg,
		privkey:   privkey,
		generator: generator,
	}
}

func (d RSAPKCS15KeyDecrypt) Algorithm() jwa.KeyEncryptionAlgorithm {
	return d.alg
}

func (d RSAPKCS15KeyDecrypt) KeyDecrypt(enckey []byte) ([]byte, error) {
	// Hey, these notes and workarounds were stolen from go-jose
	defer func() {
		// DecryptPKCS1v15SessionKey sometimes panics on an invalid payload
		// because of an index out of bounds error, which we want to ignore.
		// This has been fixed in Go 1.3.1 (released 2014/08/13), the recover()
		// only exists for preventing crashes with unpatched versions.
		// See: https://groups.google.com/forum/#!topic/golang-dev/7ihX6Y6kx9k
		// See: https://code.google.com/p/go/source/detail?r=58ee390ff31602edb66af41ed10901ec95904d33
		_ = recover()
	}()

	// Perform some input validation.
	keyBytes := d.privkey.PublicKey.N.BitLen() / 8
	if keyBytes != len(enckey) {
		// Input size is incorrect, the encrypted payload should always match
		// the size of the public modulus (e.g. using a 2048 bit key will
		// produce 256 bytes of output). Reject this since it's invalid input.
		return nil, errors.New("input size for key decrypt is incorrect")
	}

	cek, err := d.generator.KeyGenerate()
	if err != nil {
		return nil, errors.New("failed to generate key")
	}

	// When decrypting an RSA-PKCS1v1.5 payload, we must take precautions to
	// prevent chosen-ciphertext attacks as described in RFC 3218, "Preventing
	// the Million Message Attack on Cryptographic Message Syntax". We are
	// therefore deliberatly ignoring errors here.
	_ = rsa.DecryptPKCS1v15SessionKey(rand.Reader, d.privkey, enckey, cek)

	return cek, nil
}

type RSAOAEPKeyDecrypt struct {
	alg     jwa.KeyEncryptionAlgorithm
	privkey *rsa.PrivateKey
}

func NewRSAOAEPKeyDecrypt(alg jwa.KeyEncryptionAlgorithm, privkey *rsa.PrivateKey) *RSAOAEPKeyDecrypt {
	return &RSAOAEPKeyDecrypt{
		alg:     alg,
		privkey: privkey,
	}
}

func (d RSAOAEPKeyDecrypt) Algorithm() jwa.KeyEncryptionAlgorithm {
	return d.alg
}

func (d RSAOAEPKeyDecrypt) KeyDecrypt(enckey []byte) ([]byte, error) {
	var hash hash.Hash
	switch d.alg {
	case jwa.RSA_OAEP:
		hash = sha1.New()
	case jwa.RSA_OAEP_256:
		hash = sha256.New()
	default:
		return nil, ErrUnsupportedAlgorithm
	}
	return rsa.DecryptOAEP(hash, rand.Reader, d.privkey, enckey, []byte{})
}

/*** these seem to be unused or something ***/
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
