package jwebb

import (
	"crypto/aes"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwe/internal/keyenc"
)

// AES key wrap decryption functions

const (
	A128KW = "A128KW"
	A192KW = "A192KW"
	A256KW = "A256KW"
)

func KeyEncryptionIsAESKW(alg string) bool {
	switch alg {
	case A128KW, A192KW, A256KW:
		return true
	default:
		return false
	}
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