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

func RegisterVerifier2(alg jwa.SignatureAlgorithm, verifier Verifier2) {
	muVerifier2DB.Lock()
	verifier2DB[alg] = verifier
	muVerifier2DB.Unlock()
}

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

// RegisterVerifier is used to register a factory object that creates
// Verifier objects based on the given algorithm.
//
// For example, if you would like to provide a custom verifier for
// jwa.EdDSA, use this function to register a `VerifierFactory`
// (probably in your `init()`)
//
// Unlike the `UnregisterVerifier` function, this function automatically
// calls `jwa.RegisterSignatureAlgorithm` to register the algorithm
// in this module's algorithm database.
func RegisterVerifier(alg jwa.SignatureAlgorithm, f VerifierFactory) {
	jwa.RegisterSignatureAlgorithm(alg)
	muVerifierDB.Lock()
	verifierDB[alg] = f
	muVerifierDB.Unlock()
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
