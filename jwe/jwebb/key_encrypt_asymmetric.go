package jwebb

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"github.com/lestrrat-go/jwx/v4/internal/tokens"
	"github.com/lestrrat-go/jwx/v4/jwe/internal/keygen"
)

// KeyEncryptRSA15 encrypts the CEK using RSA PKCS#1 v1.5
func KeyEncryptRSA15(cek []byte, _ string, pubkey *rsa.PublicKey) (keygen.ByteSource, error) {
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, pubkey, cek)
	if err != nil {
		return nil, fmt.Errorf(`failed to encrypt using PKCS1v15: %w`, err)
	}
	return keygen.ByteKey(encrypted), nil
}

// KeyEncryptRSAOAEP encrypts the CEK using RSA OAEP
func KeyEncryptRSAOAEP(cek []byte, alg string, pubkey *rsa.PublicKey) (keygen.ByteSource, error) {
	var hash hash.Hash
	switch alg {
	case tokens.RSA_OAEP:
		hash = sha1.New()
	case tokens.RSA_OAEP_256:
		hash = sha256.New()
	case tokens.RSA_OAEP_384:
		hash = sha512.New384()
	case tokens.RSA_OAEP_512:
		hash = sha512.New()
	default:
		return nil, fmt.Errorf(`failed to generate key encrypter for RSA-OAEP: RSA_OAEP/RSA_OAEP_256/RSA_OAEP_384/RSA_OAEP_512 required`)
	}

	encrypted, err := rsa.EncryptOAEP(hash, rand.Reader, pubkey, cek, []byte{})
	if err != nil {
		return nil, fmt.Errorf(`failed to OAEP encrypt: %w`, err)
	}
	return keygen.ByteKey(encrypted), nil
}
