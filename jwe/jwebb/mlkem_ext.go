package jwebb

import (
	"fmt"
	"sync"

	"github.com/lestrrat-go/jwx/v4/jwe/internal/keygen"
)

// MLKEMKeyEncrypter is implemented by raw public key types that can
// perform ML-KEM key encapsulation for JWE. This allows external modules
// (e.g., github.com/jwx-go/mlkem) to provide ML-KEM support without
// pulling the implementation into the core jwx module.
//
// When jwe.Encrypt encounters a raw key implementing this interface
// in the ML-KEM path, it delegates encryption to the key itself.
type MLKEMKeyEncrypter interface {
	// EncryptMLKEM encapsulates a shared secret and derives/wraps the CEK.
	//
	// alg is the ML-KEM algorithm identifier (e.g., "ML-KEM-768",
	// "ML-KEM-1024+A256KW"). calg is the content encryption algorithm,
	// bound into the KDF per draft-ietf-jose-pqc-kem. For direct
	// variants, sealedCEK is the derived CEK itself; for +AnnnKW
	// variants, sealedCEK is the AES key-wrapped CEK. enc is the ML-KEM
	// ciphertext that goes into the JWE "ek" header field.
	EncryptMLKEM(cek []byte, alg, calg string) (sealedCEK, enc []byte, err error)
}

// MLKEMKeyDecrypter is implemented by raw private key types that can
// perform ML-KEM key decapsulation for JWE.
type MLKEMKeyDecrypter interface {
	// DecryptMLKEM decapsulates the shared secret and recovers the CEK.
	//
	// alg is the ML-KEM algorithm identifier. calg is the content
	// encryption algorithm, bound into the KDF per draft-ietf-jose-pqc-kem.
	// sealedCEK is the direct or AES-wrapped CEK from the JWE
	// Encrypted Key field. enc is the ML-KEM ciphertext from the "ek"
	// header field.
	DecryptMLKEM(sealedCEK []byte, alg, calg string, enc []byte) ([]byte, error)
}

// KeyEncryptMLKEMCustom encrypts using a custom ML-KEM key encrypter.
func KeyEncryptMLKEMCustom(cek []byte, alg, calg string, enc MLKEMKeyEncrypter) (keygen.ByteSource, error) {
	sealedCEK, encKey, err := enc.EncryptMLKEM(cek, alg, calg)
	if err != nil {
		return nil, fmt.Errorf(`ML-KEM key encrypt (custom): %w`, err)
	}

	return keygen.ByteWithEncapsulatedKey{
		ByteKey:    keygen.ByteKey(sealedCEK),
		Ciphertext: encKey,
	}, nil
}

// KeyDecryptMLKEMCustom decrypts using a custom ML-KEM key decrypter.
func KeyDecryptMLKEMCustom(sealedCEK []byte, alg, calg string, dec MLKEMKeyDecrypter, enc []byte) ([]byte, error) {
	cek, err := dec.DecryptMLKEM(sealedCEK, alg, calg, enc)
	if err != nil {
		return nil, fmt.Errorf(`ML-KEM key decrypt (custom): %w`, err)
	}
	return cek, nil
}

var (
	muMLKEMAlgs       sync.RWMutex
	mlkemAlgSet       = map[string]struct{}{}
	mlkemDirectAlgSet = map[string]struct{}{}
)

// RegisterMLKEMAlgorithm registers an algorithm identifier as an ML-KEM
// algorithm. After registration, IsMLKEM returns true for this identifier,
// causing the JWE encrypt/decrypt dispatch to route it through the
// ML-KEM path. Registration is idempotent.
//
// This is a privileged extension point — see [RegisterHPKEAlgorithm]
// for the full design discussion of override semantics and supply-
// chain considerations. The same rules apply: override is allowed by
// design, callers must audit their import graph, and companion modules
// calling this from init() must check the returned error and panic on
// failure to stay forward-compatible.
func RegisterMLKEMAlgorithm(alg string) error {
	muMLKEMAlgs.Lock()
	defer muMLKEMAlgs.Unlock()
	mlkemAlgSet[alg] = struct{}{}
	return nil
}

// RegisterMLKEMDirectAlgorithm registers an algorithm identifier as a
// direct (non-key-wrapping) ML-KEM algorithm. Direct algorithms use the
// derived shared secret as the CEK. Implementations should also call
// RegisterMLKEMAlgorithm for the same identifier.
//
// This is a privileged extension point — see [RegisterHPKEAlgorithm]
// for override semantics. Companion modules calling this from init()
// must check the returned error and panic on failure to stay forward-
// compatible.
func RegisterMLKEMDirectAlgorithm(alg string) error {
	muMLKEMAlgs.Lock()
	defer muMLKEMAlgs.Unlock()
	mlkemDirectAlgSet[alg] = struct{}{}
	return nil
}

func isRegisteredMLKEM(alg string) bool {
	muMLKEMAlgs.RLock()
	defer muMLKEMAlgs.RUnlock()
	_, ok := mlkemAlgSet[alg]
	return ok
}

func isRegisteredMLKEMDirect(alg string) bool {
	muMLKEMAlgs.RLock()
	defer muMLKEMAlgs.RUnlock()
	_, ok := mlkemDirectAlgSet[alg]
	return ok
}
