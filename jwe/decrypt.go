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

	// Direct-mode key management (RFC 7518 §4.5 "dir", §4.6 bare ECDH-ES, and
	// direct ML-KEM) derives the CEK without an encrypted key, so the JWE
	// Encrypted Key must be the empty octet sequence. Enforce this here, before
	// the KeyDecrypter branch, so a tampered message carrying a stray
	// encrypted_key is rejected on every path -- including caller-supplied
	// custom decrypters. IsMLKEMDirect consults a runtime registry that is
	// empty unless the ML-KEM companion module is imported, so this clause is a
	// no-op in builds without ML-KEM.
	directMode := jwebb.IsDirect(algStr) || jwebb.IsMLKEMDirect(algStr)
	if !directMode && jwebb.IsECDHES(algStr) {
		// ECDH-ES+A*KW (keywrap == true) legitimately carries an encrypted_key;
		// only bare ECDH-ES is direct. Reuse the same helper the ECDH-ES path
		// uses to determine keywrap.
		if _, _, keywrap, err := jwebb.KeyEncryptionECDHESKeySize(algStr, ctx.ctalg.String()); err == nil {
			directMode = !keywrap
		}
	}
	if directMode && len(recipientKey) != 0 {
		return nil, fmt.Errorf(`jwe: decrypt key: %q requires an empty encrypted_key`, algStr)
	}

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
	// The empty-encrypted_key invariant for "dir" (RFC 7518 §4.5) is enforced
	// in decryptCEK ahead of the KeyDecrypter branch, so it covers every path.
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

	// Parse p2c into int64 directly. Float64 cannot represent integers
	// above 2^53 exactly; comparing a parsed value against a high
	// MaxPBES2Count cap in float-space and then casting via int(...) lets
	// out-of-range values silently round into the accepted range, which
	// would defeat the cap when callers raise it past 2^53. int64 keeps
	// the bound check exact.
	var count int64
	switch v := countV.(type) {
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) || math.Trunc(v) != v {
			return nil, fmt.Errorf(`jwe: decrypt key: invalid 'p2c' value: not a positive integer (got %v)`, v)
		}
		// Reject values outside int64 range before casting; the cast
		// of an out-of-range float to int is implementation-defined.
		// Use explicit float-domain bounds (2^63 / -2^63) instead of
		// math.MaxInt64 / MinInt64 so the comparison is independent
		// of the platform's int width and the constants do not need
		// implicit conversion.
		const (
			int64MaxAsFloat = float64(1 << 63) // 2^63, the smallest float > MaxInt64
			int64MinAsFloat = -int64MaxAsFloat // -2^63, exact float = MinInt64
		)
		if v >= int64MaxAsFloat || v < int64MinAsFloat {
			return nil, fmt.Errorf(`jwe: decrypt key: invalid 'p2c' value: not representable as int64 (got %v)`, v)
		}
		count = int64(v)
	case stdjson.Number:
		c, err := v.Int64()
		if err != nil {
			return nil, fmt.Errorf(`jwe: decrypt key: invalid 'p2c' value: %q is not a valid integer: %w`, v.String(), err)
		}
		count = c
	default:
		return nil, fmt.Errorf(`jwe: decrypt key: %q field is not a number`, CountKey)
	}

	if count < int64(minCount) {
		return nil, fmt.Errorf(`jwe: decrypt key: invalid 'p2c' value: %d is below WithMinPBES2Count=%d (RFC 7518 §4.8.1.2 floor; loosen via jwe.WithMinPBES2Count)`, count, minCount)
	}
	if count > int64(maxCount) {
		return nil, fmt.Errorf(`jwe: decrypt key: invalid 'p2c' value: %d exceeds WithMaxPBES2Count=%d (DoS amplification cap; raise via jwe.WithMaxPBES2Count)`, count, maxCount)
	}

	saltBytes, err := base64.DecodeString(saltB64)
	if err != nil {
		return nil, fmt.Errorf(`jwe: decrypt key: failed to decode 'p2s': %w`, err)
	}

	// RFC 7518 §4.8.1.1 requires the salt input to be at least 8 octets.
	// This is a hard floor and is not loosenable via an option.
	if len(saltBytes) < 8 {
		return nil, fmt.Errorf(`jwe: decrypt key: invalid 'p2s' value: salt is %d octets, RFC 7518 §4.8.1.1 requires at least 8`, len(saltBytes))
	}

	salt := []byte(alg)
	salt = append(salt, byte(0))
	salt = append(salt, saltBytes...)
	return jwebb.KeyDecryptPBES2(recipientKey, recipientKey, alg, password, salt, int(count))
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

	// RFC 7518 §4.6: for bare ECDH-ES (keywrap == false) the CEK is derived
	// directly and the JWE Encrypted Key must be the empty octet sequence.
	// That invariant is enforced in decryptCEK ahead of the KeyDecrypter
	// branch so it covers every path; ECDH-ES+A*KW legitimately carries an
	// encrypted_key.

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
