package jwe

import (
	"crypto/ecdsa"
	stdjson "encoding/json"
	"fmt"
	"math"

	"github.com/lestrrat-go/jwx/v4/internal/base64"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe/internal/content_crypt"
	"github.com/lestrrat-go/jwx/v4/jwe/jwebb"
	"github.com/lestrrat-go/jwx/v4/jwk"
)

// decryptCEKContext holds algorithm-agnostic context needed during CEK decryption.
type decryptCEKContext struct {
	maxPBES2Count int
	minPBES2Count int
	ctalg         jwa.ContentEncryptionAlgorithm
	contentCipher content_crypt.Cipher
}

// decryptCEK dispatches key decryption to the appropriate per-family
// function based on the algorithm. Each function extracts its own
// algorithm-specific parameters from the merged headers.
func decryptCEK(alg jwa.KeyEncryptionAlgorithm, key any, msg *Message, recipient Recipient, headers Headers, ctx *decryptCEKContext) ([]byte, error) {
	algStr := alg.String()
	recipientKey := recipient.EncryptedKey()

	if kd, ok := key.(KeyDecrypter); ok {
		return kd.DecryptKey(alg, recipientKey, recipient, msg)
	}

	switch {
	case jwebb.IsDirect(algStr):
		return decryptKeyDirect(recipientKey, algStr, key)
	case jwebb.IsPBES2(algStr):
		return decryptKeyPBES2(recipientKey, algStr, key, headers, ctx.maxPBES2Count, ctx.minPBES2Count)
	case jwebb.IsAESGCMKW(algStr):
		return decryptKeyAESGCMKW(recipientKey, algStr, key, headers)
	case jwebb.IsECDHES(algStr):
		return decryptKeyECDHES(recipientKey, algStr, ctx.ctalg, key, headers)
	case jwebb.IsMLKEM(algStr):
		return decryptKeyMLKEM(recipientKey, algStr, ctx.ctalg, key, headers)
	case jwebb.IsHPKE(algStr):
		return decryptKeyHPKE(recipientKey, algStr, ctx.ctalg, key, headers)
	case jwebb.IsRSA15(algStr):
		return decryptKeyRSA15(recipientKey, algStr, key, ctx.contentCipher)
	case jwebb.IsRSAOAEP(algStr):
		return decryptKeyRSAOAEP(recipientKey, algStr, key)
	case jwebb.IsAESKW(algStr):
		return decryptKeyAESKW(recipientKey, algStr, key)
	default:
		return nil, fmt.Errorf(`jwe: decrypt key: unsupported algorithm (%s)`, algStr)
	}
}

func decryptKeyDirect(recipientKey []byte, alg string, key any) ([]byte, error) {
	cek, err := requireByteKey(key, alg)
	if err != nil {
		return nil, err
	}
	return jwebb.KeyDecryptDirect(recipientKey, recipientKey, alg, cek)
}

func decryptKeyPBES2(recipientKey []byte, alg string, key any, headers Headers, maxCount, minCount int) ([]byte, error) {
	password, err := requireByteKey(key, alg)
	if err != nil {
		return nil, err
	}

	saltV, ok := headers.Field(SaltKey)
	if !ok {
		return nil, fmt.Errorf(`jwe: decrypt key: missing %q field for PBES2`, SaltKey)
	}
	saltB64, ok := saltV.(string)
	if !ok {
		return nil, fmt.Errorf(`jwe: decrypt key: %q field is not a string`, SaltKey)
	}

	countV, ok := headers.Field(CountKey)
	if !ok {
		return nil, fmt.Errorf(`jwe: decrypt key: missing %q field for PBES2`, CountKey)
	}
	var countFlt float64
	switch v := countV.(type) {
	case float64:
		countFlt = v
	case stdjson.Number:
		var err error
		countFlt, err = v.Float64()
		if err != nil {
			return nil, fmt.Errorf(`jwe: decrypt key: %q field is not a valid number: %w`, CountKey, err)
		}
	default:
		return nil, fmt.Errorf(`jwe: decrypt key: %q field is not a number`, CountKey)
	}

	if math.IsNaN(countFlt) || math.IsInf(countFlt, 0) || math.Trunc(countFlt) != countFlt {
		return nil, fmt.Errorf("jwe: decrypt key: invalid 'p2c' value")
	}

	if countFlt > float64(maxCount) || countFlt < float64(minCount) {
		return nil, fmt.Errorf("jwe: decrypt key: invalid 'p2c' value")
	}

	saltBytes, err := base64.DecodeString(saltB64)
	if err != nil {
		return nil, fmt.Errorf(`jwe: decrypt key: failed to decode 'p2s': %w`, err)
	}

	salt := []byte(alg)
	salt = append(salt, byte(0))
	salt = append(salt, saltBytes...)
	return jwebb.KeyDecryptPBES2(recipientKey, recipientKey, alg, password, salt, int(countFlt))
}

func decryptKeyAESGCMKW(recipientKey []byte, alg string, key any, headers Headers) ([]byte, error) {
	sharedkey, err := requireByteKey(key, alg)
	if err != nil {
		return nil, err
	}

	var keyiv, keytag []byte
	if ivV, ok := headers.Field(InitializationVectorKey); ok {
		ivB64, ok := ivV.(string)
		if !ok {
			return nil, fmt.Errorf(`jwe: decrypt key: %q is not a string`, InitializationVectorKey)
		}
		keyiv, err = base64.DecodeString(ivB64)
		if err != nil {
			return nil, fmt.Errorf(`jwe: decrypt key: failed to decode 'iv': %w`, err)
		}
	}
	if tagV, ok := headers.Field(TagKey); ok {
		tagB64, ok := tagV.(string)
		if !ok {
			return nil, fmt.Errorf(`jwe: decrypt key: %q is not a string`, TagKey)
		}
		keytag, err = base64.DecodeString(tagB64)
		if err != nil {
			return nil, fmt.Errorf(`jwe: decrypt key: failed to decode 'tag': %w`, err)
		}
	}
	return jwebb.KeyDecryptAESGCMKW(recipientKey, recipientKey, alg, sharedkey, keyiv, keytag)
}

func decryptKeyECDHES(recipientKey []byte, alg string, ctalg jwa.ContentEncryptionAlgorithm, key any, headers Headers) ([]byte, error) {
	ctalgStr := ctalg.String()
	derivedAlg, keysize, keywrap, err := jwebb.KeyEncryptionECDHESKeySize(alg, ctalgStr)
	if err != nil {
		return nil, fmt.Errorf(`jwe: decrypt key: failed to determine ECDH-ES key size: %w`, err)
	}

	// Extract ephemeral public key from headers
	epkV, ok := headers.Field(EphemeralPublicKeyKey)
	if !ok {
		return nil, fmt.Errorf(`jwe: decrypt key: missing 'epk' field for ECDH-ES`)
	}

	var pubkey any
	switch epk := epkV.(type) {
	case jwk.ECDSAPublicKey:
		pubkey, err = jwk.Export[*ecdsa.PublicKey](epk)
		if err != nil {
			return nil, fmt.Errorf(`jwe: decrypt key: failed to export ECDSA public key: %w`, err)
		}
	case jwk.OKPPublicKey:
		pubkey, err = jwk.Export[any](epk)
		if err != nil {
			return nil, fmt.Errorf(`jwe: decrypt key: failed to export OKP public key: %w`, err)
		}
	default:
		return nil, fmt.Errorf("jwe: decrypt key: unexpected 'epk' type %T for %s", epk, alg)
	}

	var apu, apv []byte
	if v, ok := headers.AgreementPartyUInfo(); ok && len(v) > 0 {
		apu = v
	}
	if v, ok := headers.AgreementPartyVInfo(); ok && len(v) > 0 {
		apv = v
	}

	deriver, err := jwebb.NewECDHESKeyDeriver(key)
	if err != nil {
		return nil, fmt.Errorf(`jwe: decrypt key: %w`, err)
	}

	return jwebb.KeyDecryptECDHESCustom(recipientKey, derivedAlg, apu, apv, deriver, pubkey, keysize, keywrap)
}

func decryptKeyHPKE(recipientKey []byte, alg string, ctalg jwa.ContentEncryptionAlgorithm, key any, headers Headers) ([]byte, error) {
	ctalgStr := ctalg.String()

	ek, ok := headers.EncapsulatedKey()
	if !ok {
		return nil, makeHPKEError(`decrypt key (HPKE): missing 'ek' field`)
	}

	cek, err := jwebb.KeyDecryptHPKEKE(recipientKey, alg, ctalgStr, key, ek)
	if err != nil {
		return nil, makeHPKEError(`decrypt key (HPKE): %w`, err)
	}
	return cek, nil
}

func decryptKeyMLKEM(recipientKey []byte, alg string, ctalg jwa.ContentEncryptionAlgorithm, key any, headers Headers) ([]byte, error) {
	ctalgStr := ctalg.String()

	ek, ok := headers.EncapsulatedKey()
	if !ok {
		return nil, fmt.Errorf(`jwe: decrypt key: missing 'ek' field for ML-KEM`)
	}

	dec, err := mlkemDecrypterFromKey(key)
	if err != nil {
		return nil, fmt.Errorf(`jwe: decrypt key: %w`, err)
	}
	return jwebb.KeyDecryptMLKEMCustom(recipientKey, alg, ctalgStr, dec, ek)
}

// mlkemDecrypterFromKey is the decrypt-side counterpart to
// mlkemEncrypterFromKey. See its doc for the conversion strategy.
func mlkemDecrypterFromKey(key any) (jwebb.MLKEMKeyDecrypter, error) {
	if d, ok := key.(jwebb.MLKEMKeyDecrypter); ok {
		return d, nil
	}
	jkey, ok := key.(jwk.Key)
	if !ok {
		imported, err := jwk.Import[jwk.Key](key)
		if err != nil {
			return nil, fmt.Errorf(`ML-KEM: cannot convert %T (import github.com/jwx-go/mlkem/v4 to enable ML-KEM): %w`, key, err)
		}
		jkey = imported
	}
	return jwk.Export[jwebb.MLKEMKeyDecrypter](jkey)
}

func decryptKeyRSA15(recipientKey []byte, _ string, key any, contentCipher content_crypt.Cipher) ([]byte, error) {
	keysize := contentCipher.KeySize() / 2
	return jwebb.KeyDecryptRSA15(recipientKey, recipientKey, key, keysize)
}

func decryptKeyRSAOAEP(recipientKey []byte, alg string, key any) ([]byte, error) {
	return jwebb.KeyDecryptRSAOAEP(recipientKey, recipientKey, alg, key)
}

func decryptKeyAESKW(recipientKey []byte, alg string, key any) ([]byte, error) {
	sharedkey, err := requireByteKey(key, alg)
	if err != nil {
		return nil, err
	}
	return jwebb.KeyDecryptAESKW(recipientKey, recipientKey, alg, sharedkey)
}
