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

// validateAlgorithmForKey checks that alg is family-compatible with
// key at the WithKey option boundary, surfacing wrong-shape mismatches
// as crisp `jwe.WithKey: ...` errors instead of nested errors deep in
// the dispatcher (e.g. requireByteKey inside the AESKW path). Mirrors
// jws.validateAlgorithmForKey in spirit but is shaped to JWE's
// per-family key conventions.
//
// Permissive carve-outs (return nil, deferring validation):
//
//   - Untyped/extension algorithms: HPKE and ML-KEM. These are
//     extension-pluggable via Register{HPKE,MLKEM}Algorithm; an
//     extension may accept arbitrary key shapes (e.g. an
//     HPKEKeyEncrypter raw type), so the option-time gate cannot
//     enforce a closed-set rule. The downstream dispatch handles
//     unsupported shapes via a typed error.
//   - jwk.Key: the dispatcher unwraps via jwk.Export to a raw key,
//     so the kty-vs-alg check happens then.
//   - Nil key: legitimate for `dir` (caller provides CEK separately
//     via WithCEK) and for callers exploring the API.
//
// All other built-in algorithm families enforce a concrete key-shape
// expectation here. The error is wrapped by the WithKey site so the
// caller sees `jwe.WithKey: ...` consistently.
func validateAlgorithmForKey(alg jwa.KeyEncryptionAlgorithm, key any) error {
	if key == nil {
		return nil
	}
	// jwk.Key wrappers: defer to dispatch-time kty validation.
	if _, ok := key.(jwk.Key); ok {
		return nil
	}
	// Caller-supplied KeyEncrypter / KeyDecrypter implementations
	// take responsibility for their own key-shape validation. Defer.
	if _, ok := key.(KeyEncrypter); ok {
		return nil
	}
	if _, ok := key.(KeyDecrypter); ok {
		return nil
	}
	// HPKE raw key types implementing the HPKE key interfaces are
	// extension-pluggable; defer.
	if _, ok := key.(jwebb.HPKEKeyEncrypter); ok {
		return nil
	}
	if _, ok := key.(jwebb.HPKEKeyDecrypter); ok {
		return nil
	}

	algStr := alg.String()
	switch {
	case jwebb.IsHPKE(algStr) || jwebb.IsMLKEM(algStr) || jwebb.IsMLKEMDirect(algStr):
		// Extension-pluggable; key shape is the extension's contract.
		return nil
	case jwebb.IsDirect(algStr):
		// "dir" requires a byte slice (the CEK) or a symmetric jwk.
		if _, ok := key.([]byte); !ok {
			return fmt.Errorf(`algorithm %q requires a []byte key (got %T)`, algStr, key)
		}
	case jwebb.IsAESKW(algStr) || jwebb.IsAESGCMKW(algStr) || jwebb.IsPBES2(algStr):
		if _, ok := key.([]byte); !ok {
			return fmt.Errorf(`algorithm %q requires a []byte key (got %T)`, algStr, key)
		}
	case jwebb.IsRSA15(algStr) || jwebb.IsRSAOAEP(algStr):
		switch key.(type) {
		case *rsa.PublicKey, rsa.PublicKey, *rsa.PrivateKey, rsa.PrivateKey:
		default:
			return fmt.Errorf(`algorithm %q requires an RSA key (got %T)`, algStr, key)
		}
	case jwebb.IsECDHES(algStr):
		switch key.(type) {
		case *ecdsa.PublicKey, ecdsa.PublicKey, *ecdsa.PrivateKey, ecdsa.PrivateKey,
			*ecdh.PublicKey, ecdh.PublicKey, *ecdh.PrivateKey, ecdh.PrivateKey:
		default:
			return fmt.Errorf(`algorithm %q requires an ECDSA or ECDH key (got %T)`, algStr, key)
		}
	default:
		// Unknown algorithm family: defer to dispatch.
		return nil
	}
	return nil
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
