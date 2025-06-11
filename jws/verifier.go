package jws

import (
	"fmt"
	"sync"

	"github.com/lestrrat-go/jwx/v3/jwa"
)

type Verifier2 interface {
	Do(payload, protected, signature []byte, encoder Base64Encoder, encodePayload bool, key any) error

	// Create implements VerifierFactory, but this is actually a no-op,
	// and will return an error if called. This is a hack to allow
	// passing Verifier2 objects to RegisterVerifier
	Create() (Verifier, error)
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
// Please note that while this function takes a `VerifierFactory`
// as an argument, this is only so for backwards compatibility,
// and as of this writing you should use objects that implement
// the `Verifier2` interface instead.
//
// Unlike the `UnregisterVerifier` function, this function automatically
// calls `jwa.RegisterSignatureAlgorithm` to register the algorithm
// in this module's algorithm database.
func RegisterVerifier(alg jwa.SignatureAlgorithm, f VerifierFactory) {
	jwa.RegisterSignatureAlgorithm(alg)
	switch v := f.(type) {
	case Verifier2:
		muVerifier2DB.Lock()
		verifier2DB[alg] = v
		muVerifier2DB.Unlock()
	default:
		muVerifierDB.Lock()
		verifierDB[alg] = f
		muVerifierDB.Unlock()
	}
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
