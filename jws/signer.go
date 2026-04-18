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

var signerDB sync.Map // map[jwa.SignatureAlgorithm]Signer

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
	if v, ok := signerDB.Load(alg); ok {
		//nolint:forcetypeassert
		return v.(Signer), nil // always stored as Signer
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
//
// Built-in algorithm identifiers are reserved; attempts to register a Signer
// using a built-in name with different metadata will fail. Re-registering the
// exact built-in algorithm value is allowed.
func RegisterSigner(alg jwa.SignatureAlgorithm, s Signer) error {
	if err := jwa.RegisterSignatureAlgorithm(alg); err != nil {
		return fmt.Errorf(`jws.RegisterSigner: failed to register signature algorithm: %w`, err)
	}
	signerDB.Store(alg, s)
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
//
// The error return is reserved for future validation (for example,
// refusing to unregister a built-in algorithm) and is always nil
// today. Callers — especially those scripting
// Register/Unregister cycles from init() — should check the
// returned value and propagate on failure to stay
// forward-compatible, matching the convention on [RegisterSigner].
func UnregisterSigner(alg jwa.SignatureAlgorithm) error {
	signerDB.Delete(alg)
	return nil
}

type noneSigner struct{}

func (noneSigner) Sign(_ any, _ []byte) ([]byte, error) {
	return nil, nil
}
