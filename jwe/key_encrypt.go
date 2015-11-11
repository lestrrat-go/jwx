package jwe

import (
	"crypto"
	"crypto/aes"

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
