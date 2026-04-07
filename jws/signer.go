package jws

import (
	"fmt"
	"sync"

	"github.com/lestrrat-go/jwx/v4/jwa"
)

// Signer is an interface for objects that can sign payloads.
//
// Custom signing algorithms can be registered by implementing this
// interface and calling RegisterSigner.
type Signer interface {
	// Sign takes a key and a payload, and returns the signature for the payload.
	// The key type is restricted by the signature algorithm that this
	// signer is associated with.
	Sign(key any, payload []byte) ([]byte, error)
}

// SignerFunc is a function type that implements the Signer interface.
type SignerFunc func(key any, payload []byte) ([]byte, error)

func (f SignerFunc) Sign(key any, payload []byte) ([]byte, error) {
	return f(key, payload)
}

var muSignerDB sync.RWMutex
var signerDB = make(map[jwa.SignatureAlgorithm]Signer)

func init() {
	// register the signers using jwsbb. These will be used by default.
	for _, alg := range jwa.SignatureAlgorithms() {
		if alg == jwa.NoSignature() {
			continue
		}

		if err := RegisterSigner(alg, defaultSigner{alg: alg}); err != nil {
			panic(fmt.Sprintf("RegisterSigner failed: %v", err))
		}
	}
}

// SignerFor returns a Signer for the given signature algorithm.
//
// If a custom Signer has been registered for the algorithm, it is returned.
// Otherwise, a default signer that delegates to jwsbb.Sign is returned.
func SignerFor(alg jwa.SignatureAlgorithm) (Signer, error) {
	muSignerDB.RLock()
	signer, ok := signerDB[alg]
	muSignerDB.RUnlock()

	if ok {
		return signer, nil
	}

	return defaultSigner{alg: alg}, nil
}

// RegisterSigner registers a custom Signer for the given algorithm.
//
// This function also calls jwa.RegisterSignatureAlgorithm to register
// the algorithm in this module's algorithm database.
//
// If you want to completely remove an algorithm, you must call
// jwa.UnregisterSignatureAlgorithm yourself after calling
// UnregisterSigner.
func RegisterSigner(alg jwa.SignatureAlgorithm, s Signer) error {
	jwa.RegisterSignatureAlgorithm(alg)
	muSignerDB.Lock()
	signerDB[alg] = s
	muSignerDB.Unlock()
	return nil
}

// UnregisterSigner removes the signer associated with the given algorithm.
//
// Note that when you call this function, the algorithm itself is
// not automatically unregistered from this module's algorithm database.
// This is because the algorithm may still be required for verification or
// some other operation (however unlikely, it is still possible).
// Therefore, in order to completely remove the algorithm, you must
// call jwa.UnregisterSignatureAlgorithm yourself.
func UnregisterSigner(alg jwa.SignatureAlgorithm) {
	muSignerDB.Lock()
	delete(signerDB, alg)
	muSignerDB.Unlock()
}

type noneSigner struct{}

func (noneSigner) Sign(_ any, _ []byte) ([]byte, error) {
	return nil, nil
}
