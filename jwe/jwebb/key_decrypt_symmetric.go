package jwebb

import (
	"crypto/aes"
	cryptocipher "crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"golang.org/x/crypto/pbkdf2"

	"github.com/lestrrat-go/jwx/v3/jwe/internal/keyenc"
)

// AES key wrap decryption functions

const (
	// AES Key Wrap algorithms
	A128KW = "A128KW"
	A192KW = "A192KW"
	A256KW = "A256KW"
	
	// AES GCM Key Wrap algorithms
	A128GCMKW = "A128GCMKW"
	A192GCMKW = "A192GCMKW"
	A256GCMKW = "A256GCMKW"
	
	// PBES2 algorithms
	PBES2_HS256_A128KW = "PBES2-HS256+A128KW"
	PBES2_HS384_A192KW = "PBES2-HS384+A192KW"
	PBES2_HS512_A256KW = "PBES2-HS512+A256KW"
	
	// Direct key agreement
	DIRECT = "dir"
)

func KeyEncryptionIsAESKW(alg string) bool {
	switch alg {
	case A128KW, A192KW, A256KW:
		return true
	default:
		return false
	}
}

func KeyEncryptionIsAESGCMKW(alg string) bool {
	switch alg {
	case A128GCMKW, A192GCMKW, A256GCMKW:
		return true
	default:
		return false
	}
}

func KeyEncryptionIsPBES2(alg string) bool {
	switch alg {
	case PBES2_HS256_A128KW, PBES2_HS384_A192KW, PBES2_HS512_A256KW:
		return true
	default:
		return false
	}
}

func KeyEncryptionIsDirect(alg string) bool {
	return alg == DIRECT
}

func KeyEncryptionIsSymmetric(alg string) bool {
	return KeyEncryptionIsAESKW(alg) || KeyEncryptionIsAESGCMKW(alg) || KeyEncryptionIsPBES2(alg) || KeyEncryptionIsDirect(alg)
}

func KeyDecryptAESKW(recipientKey, enckey []byte, alg string, sharedkey []byte) ([]byte, error) {
	block, err := aes.NewCipher(sharedkey)
	if err != nil {
		return nil, fmt.Errorf(`failed to create cipher from shared key: %w`, err)
	}

	cek, err := keyenc.Unwrap(block, enckey)
	if err != nil {
		return nil, fmt.Errorf(`failed to unwrap data: %w`, err)
	}
	return cek, nil
}

func KeyDecryptDirect(recipientKey, enckey []byte, alg string, cek []byte) ([]byte, error) {
	return cek, nil
}

func KeyDecryptPBES2(recipientKey, enckey []byte, alg string, password []byte, salt []byte, count int) ([]byte, error) {
	var hashFunc func() hash.Hash
	var keylen int
	
	switch alg {
	case PBES2_HS256_A128KW:
		hashFunc = sha256.New
		keylen = 16
	case PBES2_HS384_A192KW:
		hashFunc = sha512.New384
		keylen = 24
	case PBES2_HS512_A256KW:
		hashFunc = sha512.New
		keylen = 32
	default:
		return nil, fmt.Errorf(`unsupported PBES2 algorithm: %s`, alg)
	}
	
	// Derive key using PBKDF2
	derivedKey := pbkdf2.Key(password, salt, count, keylen, hashFunc)
	
	// Use the derived key for AES key wrap
	return KeyDecryptAESKW(recipientKey, enckey, alg, derivedKey)
}

func KeyDecryptAESGCMKW(recipientKey, enckey []byte, alg string, sharedkey []byte, iv []byte, tag []byte) ([]byte, error) {
	if len(iv) != 12 {
		return nil, fmt.Errorf("GCM requires 96-bit iv, got %d", len(iv)*8)
	}
	if len(tag) != 16 {
		return nil, fmt.Errorf("GCM requires 128-bit tag, got %d", len(tag)*8)
	}
	
	block, err := aes.NewCipher(sharedkey)
	if err != nil {
		return nil, fmt.Errorf(`failed to create new AES cipher: %w`, err)
	}
	
	aesgcm, err := cryptocipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf(`failed to create new GCM wrap: %w`, err)
	}
	
	// Combine recipient key and tag for GCM decryption
	ciphertext := recipientKey[:]
	ciphertext = append(ciphertext, tag...)
	
	jek, err := aesgcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf(`failed to decode key: %w`, err)
	}
	
	return jek, nil
}