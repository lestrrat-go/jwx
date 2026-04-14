package jwe

import (
	"crypto/rsa"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/internal/keyconv"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe/internal/keygen"
	"github.com/lestrrat-go/jwx/v4/jwe/jwebb"
	"github.com/lestrrat-go/jwx/v4/jwk"
)

// encryptKey dispatches key encryption to the appropriate algorithm-specific
// function. This is a standalone function to avoid allocating an encrypter struct.
func encryptKey(cek []byte, keyalg jwa.KeyEncryptionAlgorithm, ctalg jwa.ContentEncryptionAlgorithm, key any, apu, apv []byte, pbes2Count int) (keygen.ByteSource, error) {
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
		return jwebb.KeyEncryptPBES2(cek, algStr, password, pbes2Count)
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
		enc, err := mlkemEncrypterFromKey(key)
		if err != nil {
			return nil, fmt.Errorf(`jwe: encrypt key: %w`, err)
		}
		return jwebb.KeyEncryptMLKEMCustom(cek, algStr, ctalgStr, enc)
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

// mlkemEncrypterFromKey converts a user-supplied key value into a
// jwebb.MLKEMKeyEncrypter. ML-KEM support is provided by the
// github.com/jwx-go/mlkem companion module — its init() registers raw
// key importers (for stdlib *mlkem.EncapsulationKey768/1024) and a
// jwk.Export adapter that yields an MLKEMKeyEncrypter wrapper.
func mlkemEncrypterFromKey(key any) (jwebb.MLKEMKeyEncrypter, error) {
	if e, ok := key.(jwebb.MLKEMKeyEncrypter); ok {
		return e, nil
	}
	jkey, ok := key.(jwk.Key)
	if !ok {
		imported, err := jwk.Import[jwk.Key](key)
		if err != nil {
			return nil, fmt.Errorf(`ML-KEM: cannot convert %T (import github.com/jwx-go/mlkem/v4 to enable ML-KEM): %w`, key, err)
		}
		jkey = imported
	}
	return jwk.Export[jwebb.MLKEMKeyEncrypter](jkey)
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
