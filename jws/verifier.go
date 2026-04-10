package jws

import (
	"sync"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws/jwsbb"
)

type defaultVerifier struct {
	alg jwa.SignatureAlgorithm
}

func (v defaultVerifier) Verify(key any, payload, signature []byte) error {
	return jwsbb.Verify(key, v.alg.String(), payload, signature)
}

// Verifier is an interface for objects that can verify signatures.
//
// Custom verification algorithms can be registered by implementing this
// interface and calling RegisterVerifier.
type Verifier interface {
	Verify(key any, payload, signature []byte) error
}

// VerifierFunc is a function type that implements the Verifier interface.
type VerifierFunc func(key any, payload, signature []byte) error

func (f VerifierFunc) Verify(key any, payload, signature []byte) error {
	return f(key, payload, signature)
}

var verifierDB sync.Map // map[jwa.SignatureAlgorithm]Verifier

// VerifierFor returns a Verifier for the given signature algorithm.
//
// If a custom Verifier has been registered for the algorithm, it is returned.
// Otherwise, a default verifier that delegates to jwsbb.Verify is returned.
func VerifierFor(alg jwa.SignatureAlgorithm) (Verifier, error) {
	if v, ok := verifierDB.Load(alg); ok {
		//nolint:forcetypeassert
		return v.(Verifier), nil // always stored as Verifier
	}

	return defaultVerifier{alg: alg}, nil
}

// RegisterVerifier registers a custom Verifier for the given algorithm.
//
// This function also calls jwa.RegisterSignatureAlgorithm to register
// the algorithm in this module's algorithm database.
func RegisterVerifier(alg jwa.SignatureAlgorithm, v Verifier) error {
	jwa.RegisterSignatureAlgorithm(alg)
	verifierDB.Store(alg, v)
	return nil
}

// UnregisterVerifier removes the verifier associated with the given algorithm.
//
// Note that when you call this function, the algorithm itself is
// not automatically unregistered from this module's algorithm database.
// This is because the algorithm may still be required for signing or
// some other operation (however unlikely, it is still possible).
// Therefore, in order to completely remove the algorithm, you must
// call jwa.UnregisterSignatureAlgorithm yourself.
func UnregisterVerifier(alg jwa.SignatureAlgorithm) {
	verifierDB.Delete(alg)
}
