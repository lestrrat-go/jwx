package jws

import (
	"fmt"
	"sync"

	"github.com/lestrrat-go/jwx/v3/jwa"
)

type Signer2 interface {
	Algorithm() jwa.SignatureAlgorithm
	Sign(payload, protected []byte, encoder Base64Encoder, encodePayload bool, key any) ([]byte, error)
}

// RawSigner is an interface that allows you to sign raw data, presumably
// the combined buffer containing the JWS header and payload. This interface
// is only required for JWT signing taking the fastpath.
type RawSigner interface {
	SignRaw(key any, raw []byte) ([]byte, error)
}

var muSigner2DB sync.RWMutex
var signer2DB = make(map[jwa.SignatureAlgorithm]Signer2)

type SignerFactory interface {
	Create() (Signer, error)
}
type SignerFactoryFn func() (Signer, error)

func (fn SignerFactoryFn) Create() (Signer, error) {
	return fn()
}

var muSignerDB sync.RWMutex
var signerDB = make(map[jwa.SignatureAlgorithm]SignerFactory)

// RegisterSigner is used to register a signer for the given
// algorithm.
//
// Please note that this function is intended to be passed a
// signer object as its second argument, but due to historical
// reasons the function signature is defined as taking `any` type.
//
// You should create a signer object that implements the `Signer2`
// interface to register a signer, unless you have legacy code that
// plugged into the `SignerFactory` interface.
//
// Unlike the `UnregisterSigner` function, this function automatically
// calls `jwa.RegisterSignatureAlgorithm` to register the algorithm
// in this module's algorithm database.
func RegisterSigner(alg jwa.SignatureAlgorithm, f any) error {
	jwa.RegisterSignatureAlgorithm(alg)
	switch s := f.(type) {
	case Signer2:
		muSigner2DB.Lock()
		signer2DB[alg] = s
		muSigner2DB.Unlock()

		// delete the other signer, if there was one
		muSignerDB.Lock()
		delete(signerDB, alg)
		muSignerDB.Unlock()
	case SignerFactory:
		muSignerDB.Lock()
		signerDB[alg] = s
		muSignerDB.Unlock()

		// Remove previous signer, if there was one
		removeSigner(alg)

		muSigner2DB.Lock()
		delete(signer2DB, alg)
		muSigner2DB.Unlock()
	default:
		return fmt.Errorf(`jws.RegisterSigner: unsupported type %T for algorithm %q`, f, alg)
	}
	return nil
}

// UnregisterSigner removes the signer factory associated with
// the given algorithm, as well as the signer instance created
// by the factory.
//
// Note that when you call this function, the algorithm itself is
// not automatically unregistered from this module's algorithm database.
// This is because the algorithm may still be required for verification or
// some other operation (however unlikely, it is still possible).
// Therefore, in order to completely remove the algorithm, you must
// call `jwa.UnregisterSignatureAlgorithm` yourself.
func UnregisterSigner(alg jwa.SignatureAlgorithm) {
	muSigner2DB.Lock()
	delete(signer2DB, alg)
	muSigner2DB.Unlock()

	muSignerDB.Lock()
	delete(signerDB, alg)
	muSignerDB.Unlock()
	// Remove previous signer
	removeSigner(alg)
}

// NewSigner creates a signer that signs payloads using the given signature algorithm.
// This function is deprecated. You should use `SignerFor()` instead.
//
// This function only exists for backwards compatibility, but will not work
// unless you enable the legacy support mode by calling jws.Settings(jws.WithLegacySigners(true)).
func NewSigner(alg jwa.SignatureAlgorithm) (Signer, error) {
	muSignerDB.RLock()
	f, ok := signerDB[alg]
	muSignerDB.RUnlock()

	if ok {
		return f.Create()
	}
	return nil, fmt.Errorf(`jws.NewSigner: unsupported signature algorithm "%s"`, alg)
}

type noneSigner struct{}

func (noneSigner) Algorithm() jwa.SignatureAlgorithm {
	return jwa.NoSignature()
}

func (noneSigner) Sign([]byte, interface{}) ([]byte, error) {
	return nil, nil
}
