package jwebb

import (
	"crypto/aes"
	"crypto/mlkem"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/internal/tokens"
	"github.com/lestrrat-go/jwx/v3/jwe/internal/mlkemkdf"
)

// KeyDecryptMLKEM performs ML-KEM decapsulation for direct key agreement.
// The ek parameter is the KEM ciphertext from the "ek" header field.
func KeyDecryptMLKEM(alg string, calg string, privkey any, ek []byte) ([]byte, error) {
	sharedKey, err := mlkemDecapsulate(alg, privkey, ek)
	if err != nil {
		return nil, err
	}

	keysize, err := mlkemKeySize(alg, calg)
	if err != nil {
		return nil, err
	}

	algID := mlkemKDFAlgorithmID(alg, calg)
	return mlkemkdf.DeriveKey(sharedKey, algID, keysize), nil
}

// KeyDecryptMLKEMKeyWrap performs ML-KEM decapsulation + AES key unwrap.
// The ek parameter is the KEM ciphertext from the "ek" header field.
// The enckey parameter is the wrapped CEK from the JWE Encrypted Key field.
func KeyDecryptMLKEMKeyWrap(enckey []byte, alg string, calg string, privkey any, ek []byte) ([]byte, error) {
	sharedKey, err := mlkemDecapsulate(alg, privkey, ek)
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

	return Unwrap(block, enckey)
}

// mlkemDecapsulate dispatches to the correct ML-KEM parameter set.
func mlkemDecapsulate(alg string, privkey any, ciphertext []byte) ([]byte, error) {
	switch alg {
	case tokens.ML_KEM_768, tokens.ML_KEM_768_A192KW:
		dk, ok := privkey.(*mlkem.DecapsulationKey768)
		if !ok {
			return nil, fmt.Errorf(`ML-KEM-768: expected *mlkem.DecapsulationKey768, got %T`, privkey)
		}
		return dk.Decapsulate(ciphertext)
	case tokens.ML_KEM_1024, tokens.ML_KEM_1024_A256KW:
		dk, ok := privkey.(*mlkem.DecapsulationKey1024)
		if !ok {
			return nil, fmt.Errorf(`ML-KEM-1024: expected *mlkem.DecapsulationKey1024, got %T`, privkey)
		}
		return dk.Decapsulate(ciphertext)
	default:
		return nil, fmt.Errorf(`unsupported ML-KEM algorithm: %s`, alg)
	}
}
