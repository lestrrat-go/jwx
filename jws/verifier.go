package jws

import (
	"fmt"
	"sync"

	"github.com/lestrrat-go/jwx/v3/jwa"
)

type Verifier2 interface {
	Do(payload, protected, signature []byte, encoder Base64Encoder, encodePayload bool, key any) error
}

var muVerifier2DB sync.RWMutex
var verifier2DB = make(map[jwa.SignatureAlgorithm]Verifier2)

func verifierFor(alg jwa.SignatureAlgorithm) (Verifier2, error) {
	muVerifier2DB.RLock()
	defer muVerifier2DB.RUnlock()

	v, ok := verifier2DB[alg]
	if !ok {
		return nil, fmt.Errorf(`no verifier registered for algorithm %q`, alg)
	}
	return v, nil
}

type VerifierFactory interface {
	Create() (Verifier, error)
}
type VerifierFactoryFn func() (Verifier, error)

func (fn VerifierFactoryFn) Create() (Verifier, error) {
	return fn()
}

var muVerifierDB sync.RWMutex
var verifierDB = make(map[jwa.SignatureAlgorithm]VerifierFactory)

// RegisterVerifier is used to register a verifier for the given
// algorithm.
//
// Please note that this function is intended to be passed a
// verifier object as its second argument, but due to historical
// reasons the function signature is defined as taking `any` type.
//
// You should create a signer object that implements the `Verifier2`
// interface to register a signer, unless you have legacy code that
// plugged into the `SignerFactory` interface.
//
// Unlike the `UnregisterVerifier` function, this function automatically
// calls `jwa.RegisterSignatureAlgorithm` to register the algorithm
// in this module's algorithm database.
func RegisterVerifier(alg jwa.SignatureAlgorithm, f any) error {
	jwa.RegisterSignatureAlgorithm(alg)
	switch v := f.(type) {
	case Verifier2:
		muVerifier2DB.Lock()
		verifier2DB[alg] = v
		muVerifier2DB.Unlock()

		muVerifierDB.Lock()
		delete(verifierDB, alg)
		muVerifierDB.Unlock()
	case VerifierFactory:
		muVerifierDB.Lock()
		verifierDB[alg] = v
		muVerifierDB.Unlock()

		muVerifier2DB.Lock()
		delete(verifier2DB, alg)
		muVerifier2DB.Unlock()
	default:
		return fmt.Errorf(`jws.RegisterVerifier: unsupported type %T for algorithm %q`, f, alg)
	}
	return nil
}

// UnregisterVerifier removes the signer factory associated with
// the given algorithm.
//
// Note that when you call this function, the algorithm itself is
// not automatically unregistered from this module's algorithm database.
// This is because the algorithm may still be required for signing or
// some other operation (however unlikely, it is still possible).
// Therefore, in order to completely remove the algorithm, you must
// call `jwa.UnregisterSignatureAlgorithm` yourself.
func UnregisterVerifier(alg jwa.SignatureAlgorithm) {
	muVerifier2DB.Lock()
	delete(verifier2DB, alg)
	muVerifier2DB.Unlock()

	muVerifierDB.Lock()
	delete(verifierDB, alg)
	muVerifierDB.Unlock()
}

// NewVerifier creates a verifier that signs payloads using the given signature algorithm.
func NewVerifier(alg jwa.SignatureAlgorithm) (Verifier, error) {
	muVerifierDB.RLock()
	f, ok := verifierDB[alg]
	muVerifierDB.RUnlock()

	if ok {
		return f.Create()
	}
	return nil, fmt.Errorf(`jws.NewVerifier: unsupported signature algorithm "%s"`, alg)
}
