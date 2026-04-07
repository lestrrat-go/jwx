package jwebb

import (
	"crypto/aes"
	"crypto/mlkem"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/internal/tokens"
	"github.com/lestrrat-go/jwx/v4/jwe/internal/keygen"
	"github.com/lestrrat-go/jwx/v4/jwe/internal/mlkemkdf"
)

// mlkemKeySize returns the KDF output size for the given ML-KEM algorithm.
// For direct mode, the caller must pass the content encryption algorithm string
// as calg and this function returns the CEK size.
// For key-wrap mode, it returns the AES key size for the wrapping algorithm.
func mlkemKeySize(alg, calg string) (int, error) {
	switch alg {
	case tokens.ML_KEM_768, tokens.ML_KEM_1024:
		// Direct mode: output size matches the content encryption key size
		size, err := contentEncryptionKeySize(calg)
		if err != nil {
			return 0, err
		}
		return int(size), nil
	case tokens.ML_KEM_768_A192KW:
		return 24, nil // AES-192
	case tokens.ML_KEM_1024_A256KW:
		return 32, nil // AES-256
	default:
		return 0, fmt.Errorf(`unsupported ML-KEM algorithm %s`, alg)
	}
}

// mlkemKDFAlgorithmID returns the algorithm identifier string used in the
// KMAC256 KDF. For direct mode this is the content encryption algorithm;
// for key-wrap mode this is the key encryption algorithm itself.
func mlkemKDFAlgorithmID(alg, calg string) string {
	switch alg {
	case tokens.ML_KEM_768, tokens.ML_KEM_1024:
		return calg
	default:
		return alg
	}
}

// KeyEncryptMLKEM performs ML-KEM encapsulation for direct key agreement.
// The cek parameter is ignored — the CEK is derived from the KEM shared secret.
func KeyEncryptMLKEM(_ []byte, alg string, calg string, pubkey any) (keygen.ByteSource, error) {
	sharedKey, ciphertext, err := mlkemEncapsulate(alg, pubkey)
	if err != nil {
		return nil, err
	}

	keysize, err := mlkemKeySize(alg, calg)
	if err != nil {
		return nil, err
	}

	algID := mlkemKDFAlgorithmID(alg, calg)
	derived := mlkemkdf.DeriveKey(sharedKey, algID, keysize)

	return keygen.ByteWithEncapsulatedKey{
		ByteKey:    keygen.ByteKey(derived),
		Ciphertext: ciphertext,
	}, nil
}

// KeyEncryptMLKEMKeyWrap performs ML-KEM encapsulation + AES key wrap.
func KeyEncryptMLKEMKeyWrap(cek []byte, alg string, calg string, pubkey any) (keygen.ByteSource, error) {
	sharedKey, ciphertext, err := mlkemEncapsulate(alg, pubkey)
	if err != nil {
		return nil, err
	}

	keysize, err := mlkemKeySize(alg, calg)
	if err != nil {
		return nil, err
	}

	algID := mlkemKDFAlgorithmID(alg, calg)
	kek := mlkemkdf.DeriveKey(sharedKey, algID, keysize)

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf(`failed to create AES cipher from ML-KEM derived key: %w`, err)
	}

	wrapped, err := Wrap(block, cek)
	if err != nil {
		return nil, fmt.Errorf(`failed to wrap CEK with ML-KEM derived key: %w`, err)
	}

	return keygen.ByteWithEncapsulatedKey{
		ByteKey:    keygen.ByteKey(wrapped),
		Ciphertext: ciphertext,
	}, nil
}

// mlkemEncapsulate dispatches to the correct ML-KEM parameter set.
func mlkemEncapsulate(alg string, pubkey any) (sharedKey, ciphertext []byte, err error) {
	switch alg {
	case tokens.ML_KEM_768, tokens.ML_KEM_768_A192KW:
		ek, ok := pubkey.(*mlkem.EncapsulationKey768)
		if !ok {
			return nil, nil, fmt.Errorf(`ML-KEM-768: expected *mlkem.EncapsulationKey768, got %T`, pubkey)
		}
		ss, ct := ek.Encapsulate()
		return ss, ct, nil
	case tokens.ML_KEM_1024, tokens.ML_KEM_1024_A256KW:
		ek, ok := pubkey.(*mlkem.EncapsulationKey1024)
		if !ok {
			return nil, nil, fmt.Errorf(`ML-KEM-1024: expected *mlkem.EncapsulationKey1024, got %T`, pubkey)
		}
		ss, ct := ek.Encapsulate()
		return ss, ct, nil
	default:
		return nil, nil, fmt.Errorf(`unsupported ML-KEM algorithm: %s`, alg)
	}
}
