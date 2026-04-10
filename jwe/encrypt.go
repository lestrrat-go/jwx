package jwe

import (
	"crypto/rsa"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/internal/keyconv"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe/internal/keygen"
	"github.com/lestrrat-go/jwx/v4/jwe/jwebb"
)

// encryptKey dispatches key encryption to the appropriate algorithm-specific
// function. This is a standalone function to avoid allocating an encrypter struct.
func encryptKey(cek []byte, keyalg jwa.KeyEncryptionAlgorithm, ctalg jwa.ContentEncryptionAlgorithm, key any, apu, apv []byte) (keygen.ByteSource, error) {
	algStr := keyalg.String()
	ctalgStr := ctalg.String()

	switch {
	case jwebb.IsDirect(algStr):
		sharedkey, err := requireByteKey(key, algStr)
		if err != nil {
			return nil, err
		}
		return jwebb.KeyEncryptDirect(cek, algStr, sharedkey)
	case jwebb.IsPBES2(algStr):
		password, err := requireByteKey(key, algStr)
		if err != nil {
			return nil, err
		}
		return jwebb.KeyEncryptPBES2(cek, algStr, password)
	case jwebb.IsAESGCMKW(algStr):
		sharedkey, err := requireByteKey(key, algStr)
		if err != nil {
			return nil, err
		}
		return jwebb.KeyEncryptAESGCMKW(cek, algStr, sharedkey)
	case jwebb.IsECDHES(algStr):
		_, keysize, keywrap, err := jwebb.KeyEncryptionECDHESKeySize(algStr, ctalgStr)
		if err != nil {
			return nil, fmt.Errorf(`jwe: encrypt key: failed to determine ECDH-ES key size: %w`, err)
		}
		gen, err := jwebb.NewECDHESKeyGenerator(key)
		if err != nil {
			return nil, fmt.Errorf(`jwe: encrypt key: %w`, err)
		}
		return jwebb.KeyEncryptECDHESCustom(cek, algStr, apu, apv, gen, keysize, ctalgStr, keywrap)
	case jwebb.IsMLKEM(algStr):
		if jwebb.IsMLKEMDirect(algStr) {
			return jwebb.KeyEncryptMLKEM(cek, algStr, ctalgStr, key)
		}
		return jwebb.KeyEncryptMLKEMKeyWrap(cek, algStr, ctalgStr, key)
	case jwebb.IsHPKE(algStr):
		result, err := jwebb.KeyEncryptHPKEKE(cek, algStr, ctalgStr, key)
		if err != nil {
			return nil, makeHPKEError(`encrypt key (HPKE): %w`, err)
		}
		return result, nil
	case jwebb.IsRSA15(algStr):
		return encryptKeyRSA(cek, algStr, key, jwebb.KeyEncryptRSA15)
	case jwebb.IsRSAOAEP(algStr):
		return encryptKeyRSA(cek, algStr, key, jwebb.KeyEncryptRSAOAEP)
	case jwebb.IsAESKW(algStr):
		sharedkey, err := requireByteKey(key, algStr)
		if err != nil {
			return nil, err
		}
		return jwebb.KeyEncryptAESKW(cek, algStr, sharedkey)
	default:
		return nil, fmt.Errorf(`jwe: encrypt key: unsupported algorithm (%s)`, algStr)
	}
}

func requireByteKey(key any, alg string) ([]byte, error) {
	b, ok := key.([]byte)
	if !ok {
		return nil, fmt.Errorf("jwe: []byte is required as key for %s (got %T)", alg, key)
	}
	return b, nil
}

func encryptKeyRSA(cek []byte, alg string, key any, encryptFn func([]byte, string, *rsa.PublicKey) (keygen.ByteSource, error)) (keygen.ByteSource, error) {
	// Handle rsa.PublicKey by value - convert to pointer
	if pk, ok := key.(rsa.PublicKey); ok {
		key = &pk
	}

	pubkey, err := keyconv.RSAPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf(`jwe: encrypt key: failed to convert to RSA public key: %w`, err)
	}

	return encryptFn(cek, alg, pubkey)
}
