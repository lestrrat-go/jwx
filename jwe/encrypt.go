package jwe

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/internal/keyconv"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe/internal/keygen"
	"github.com/lestrrat-go/jwx/v4/jwe/jwebb"
)

// encrypter is responsible for taking various components to encrypt a key.
// its operation is not concurrency safe. You must provide locking yourself
//
//nolint:govet
type encrypter struct {
	apu    []byte
	apv    []byte
	ctalg  jwa.ContentEncryptionAlgorithm
	keyalg jwa.KeyEncryptionAlgorithm
	key    any
}

// newEncrypter creates a new Encrypter instance with all required parameters.
//
// key must be a resolved key in its "raw" format (e.g. *rsa.PublicKey,
// []byte, etc.) — not a jwk.Key. The caller is responsible for resolving
// jwk.Key to raw form before calling this function.
//
// You should consider this object immutable once created.
func newEncrypter(keyalg jwa.KeyEncryptionAlgorithm, ctalg jwa.ContentEncryptionAlgorithm, key any, apu, apv []byte) *encrypter {
	return &encrypter{
		apu:    apu,
		apv:    apv,
		ctalg:  ctalg,
		keyalg: keyalg,
		key:    key,
	}
}

func requireByteKey(key any, alg string) ([]byte, error) {
	b, ok := key.([]byte)
	if !ok {
		return nil, fmt.Errorf("jwe: []byte is required as key for %s (got %T)", alg, key)
	}
	return b, nil
}

func (e *encrypter) EncryptKey(cek []byte) (keygen.ByteSource, error) {
	algStr := e.keyalg.String()
	ctalgStr := e.ctalg.String()

	switch {
	case jwebb.IsDirect(algStr):
		return e.encryptKeyDirect(cek, algStr)
	case jwebb.IsPBES2(algStr):
		return e.encryptKeyPBES2(cek, algStr)
	case jwebb.IsAESGCMKW(algStr):
		return e.encryptKeyAESGCMKW(cek, algStr)
	case jwebb.IsECDHES(algStr):
		return e.encryptKeyECDHES(cek, algStr, ctalgStr)
	case jwebb.IsMLKEM(algStr):
		return e.encryptKeyMLKEM(cek, algStr, ctalgStr)
	case jwebb.IsHPKE(algStr):
		return e.encryptKeyHPKE(cek, algStr, ctalgStr)
	case jwebb.IsRSA15(algStr):
		return e.encryptKeyRSA(cek, algStr, jwebb.KeyEncryptRSA15)
	case jwebb.IsRSAOAEP(algStr):
		return e.encryptKeyRSA(cek, algStr, jwebb.KeyEncryptRSAOAEP)
	case jwebb.IsAESKW(algStr):
		return e.encryptKeyAESKW(cek, algStr)
	default:
		return nil, fmt.Errorf(`jwe: encrypt key: unsupported algorithm (%s)`, algStr)
	}
}

func (e *encrypter) encryptKeyDirect(cek []byte, alg string) (keygen.ByteSource, error) {
	sharedkey, err := requireByteKey(e.key, alg)
	if err != nil {
		return nil, err
	}
	return jwebb.KeyEncryptDirect(cek, alg, sharedkey)
}

func (e *encrypter) encryptKeyPBES2(cek []byte, alg string) (keygen.ByteSource, error) {
	password, err := requireByteKey(e.key, alg)
	if err != nil {
		return nil, err
	}
	return jwebb.KeyEncryptPBES2(cek, alg, password)
}

func (e *encrypter) encryptKeyAESGCMKW(cek []byte, alg string) (keygen.ByteSource, error) {
	sharedkey, err := requireByteKey(e.key, alg)
	if err != nil {
		return nil, err
	}
	return jwebb.KeyEncryptAESGCMKW(cek, alg, sharedkey)
}

func (e *encrypter) encryptKeyAESKW(cek []byte, alg string) (keygen.ByteSource, error) {
	sharedkey, err := requireByteKey(e.key, alg)
	if err != nil {
		return nil, err
	}
	return jwebb.KeyEncryptAESKW(cek, alg, sharedkey)
}

func (e *encrypter) encryptKeyECDHES(cek []byte, alg, ctalg string) (keygen.ByteSource, error) {
	_, keysize, keywrap, err := jwebb.KeyEncryptionECDHESKeySize(alg, ctalg)
	if err != nil {
		return nil, fmt.Errorf(`jwe: encrypt key: failed to determine ECDH-ES key size: %w`, err)
	}

	keyToUse := e.key

	// Normalize key to public key pointer form
	switch key := keyToUse.(type) {
	case *ecdsa.PublicKey:
		// already correct
	case ecdsa.PublicKey:
		keyToUse = &key
	case *ecdsa.PrivateKey:
		keyToUse = &key.PublicKey
	case ecdsa.PrivateKey:
		keyToUse = &key.PublicKey
	case *ecdh.PublicKey:
		// already correct
	case ecdh.PublicKey:
		keyToUse = &key
	case ecdh.PrivateKey:
		keyToUse = key.PublicKey()
	case *ecdh.PrivateKey:
		keyToUse = key.PublicKey()
	}

	// Handle ecdh.PublicKey (X25519 or convert to ECDSA)
	switch key := keyToUse.(type) {
	case *ecdh.PublicKey:
		if key.Curve() == ecdh.X25519() {
			if !keywrap {
				return jwebb.KeyEncryptECDHESX25519(cek, alg, e.apu, e.apv, key, keysize, ctalg)
			}
			return jwebb.KeyEncryptECDHESKeyWrapX25519(cek, alg, e.apu, e.apv, key, keysize, ctalg)
		}

		ecdsaKeyV, err := keyconv.ECDHToECDSA(key)
		if err != nil {
			return nil, fmt.Errorf(`jwe: encrypt key: failed to convert ECDH public key to ECDSA: %w`, err)
		}
		keyToUse = ecdsaKeyV
	}

	switch key := keyToUse.(type) {
	case *ecdsa.PublicKey:
		if !keywrap {
			return jwebb.KeyEncryptECDHESECDSA(cek, alg, e.apu, e.apv, key, keysize, ctalg)
		}
		return jwebb.KeyEncryptECDHESKeyWrapECDSA(cek, alg, e.apu, e.apv, key, keysize, ctalg)
	default:
		// Try custom ECDH-ES key generator (e.g., X448 from external modules)
		if gen, ok := keyToUse.(jwebb.ECDHESKeyGenerator); ok {
			return jwebb.KeyEncryptECDHESCustom(cek, alg, e.apu, e.apv, gen, keysize, ctalg, keywrap)
		}
		return nil, fmt.Errorf(`jwe: encrypt key: unsupported key type for ECDH-ES: %T`, keyToUse)
	}
}

func (e *encrypter) encryptKeyHPKE(cek []byte, alg, ctalg string) (keygen.ByteSource, error) {
	return jwebb.KeyEncryptHPKEKE(cek, alg, ctalg, e.key)
}

func (e *encrypter) encryptKeyMLKEM(cek []byte, alg, ctalg string) (keygen.ByteSource, error) {
	if jwebb.IsMLKEMDirect(alg) {
		return jwebb.KeyEncryptMLKEM(cek, alg, ctalg, e.key)
	}
	return jwebb.KeyEncryptMLKEMKeyWrap(cek, alg, ctalg, e.key)
}

func (e *encrypter) encryptKeyRSA(cek []byte, alg string, encryptFn func([]byte, string, *rsa.PublicKey) (keygen.ByteSource, error)) (keygen.ByteSource, error) {
	keyToUse := e.key

	// Handle rsa.PublicKey by value - convert to pointer
	if pk, ok := keyToUse.(rsa.PublicKey); ok {
		keyToUse = &pk
	}

	pubkey, err := keyconv.RSAPublicKey(keyToUse)
	if err != nil {
		return nil, fmt.Errorf(`jwe: encrypt key: failed to convert to RSA public key: %w`, err)
	}

	return encryptFn(cek, alg, pubkey)
}
