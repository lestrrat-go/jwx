package jwe

import "github.com/lestrrat/go-jwx/jwa"

func (c GenericContentCrypt) Algorithm() jwa.ContentEncryptionAlgorithm {
	return c.alg
}

func (c GenericContentCrypt) Encrypt(plaintext, aad []byte) ([]byte, []byte, []byte, []byte, error) {
	cek, err := c.cekgen.KeyGenerate()
	if err != nil {
		debug("cekgen.KeyGenerate failed")
		return nil, nil, nil, nil, err
	}

	iv, err := c.ivgen.KeyGenerate()
	if err != nil {
		debug("ivgen.KeyGenerate failed")
		return nil, nil, nil, nil, err
	}

	encrypted, tag, err := c.cipher.encrypt(cek, iv, plaintext, aad)
	if err != nil {
		debug("cipher.encrypt failed")
		return nil, nil, nil, nil, err
	}

	return cek, iv, encrypted, tag, nil
}

func (c GenericContentCrypt) Decrypt(cek, iv, ciphertext, tag, aad []byte) ([]byte, error) {
	return c.cipher.decrypt(cek, iv, ciphertext, tag, aad)
}

func NewAesCrypt(contentAlg jwa.ContentEncryptionAlgorithm, sharedkey []byte) (*GenericContentCrypt, error) {
	cipher, err := NewAesContentCipher(contentAlg)
	if err != nil {
		return nil, err
	}

	return &GenericContentCrypt{
		alg:     contentAlg,
		cipher:  cipher,
		cekgen:  NewRandomKeyGenerate(cipher.KeySize() * 2),
		ivgen:   NewRandomKeyGenerate(16),
		keysize: cipher.KeySize() * 2,
		tagsize: 16,
	}, nil
}

func (c GenericContentCrypt) KeySize() int {
	return c.keysize
}
