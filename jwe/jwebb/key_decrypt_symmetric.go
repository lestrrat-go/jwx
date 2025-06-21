package jwebb

import (
	"crypto/aes"
	cryptocipher "crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"golang.org/x/crypto/pbkdf2"

	"github.com/lestrrat-go/jwx/v3/internal/tokens"
)

// AES key wrap decryption functions

// Use constants from tokens package
// No need to redefine them here

func KeyEncryptionIsAESKW(alg string) bool {
	switch alg {
	case tokens.A128KW, tokens.A192KW, tokens.A256KW:
		return true
	default:
		return false
	}
}

func KeyEncryptionIsAESGCMKW(alg string) bool {
	switch alg {
	case tokens.A128GCMKW, tokens.A192GCMKW, tokens.A256GCMKW:
		return true
	default:
		return false
	}
}

func KeyEncryptionIsPBES2(alg string) bool {
	switch alg {
	case tokens.PBES2_HS256_A128KW, tokens.PBES2_HS384_A192KW, tokens.PBES2_HS512_A256KW:
		return true
	default:
		return false
	}
}

func KeyEncryptionIsDirect(alg string) bool {
	return alg == tokens.DIRECT
}

func KeyEncryptionIsSymmetric(alg string) bool {
	return KeyEncryptionIsAESKW(alg) || KeyEncryptionIsAESGCMKW(alg) || KeyEncryptionIsPBES2(alg) || KeyEncryptionIsDirect(alg)
}

func KeyDecryptAESKW(_, enckey []byte, _ string, sharedkey []byte) ([]byte, error) {
	block, err := aes.NewCipher(sharedkey)
	if err != nil {
		return nil, fmt.Errorf(`failed to create cipher from shared key: %w`, err)
	}

	cek, err := Unwrap(block, enckey)
	if err != nil {
		return nil, fmt.Errorf(`failed to unwrap data: %w`, err)
	}
	return cek, nil
}

func KeyDecryptDirect(_, _ []byte, _ string, cek []byte) ([]byte, error) {
	return cek, nil
}

func KeyDecryptPBES2(_, enckey []byte, alg string, password []byte, salt []byte, count int) ([]byte, error) {
	var hashFunc func() hash.Hash
	var keylen int

	switch alg {
	case tokens.PBES2_HS256_A128KW:
		hashFunc = sha256.New
		keylen = 16
	case tokens.PBES2_HS384_A192KW:
		hashFunc = sha512.New384
		keylen = 24
	case tokens.PBES2_HS512_A256KW:
		hashFunc = sha512.New
		keylen = 32
	default:
		return nil, fmt.Errorf(`unsupported PBES2 algorithm: %s`, alg)
	}

	// Derive key using PBKDF2
	derivedKey := pbkdf2.Key(password, salt, count, keylen, hashFunc)

	// Use the derived key for AES key wrap
	return KeyDecryptAESKW(nil, enckey, alg, derivedKey)
}

func KeyDecryptAESGCMKW(recipientKey, _ []byte, _ string, sharedkey []byte, iv []byte, tag []byte) ([]byte, error) {
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
