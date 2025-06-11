package jws

import (
	"fmt"
	"sync"

	"github.com/lestrrat-go/jwx/v3/jwa"
)

type Signer2 interface {
	Algorithm() jwa.SignatureAlgorithm
	Do(payload, protected []byte, encoder Base64Encoder, encodePayload bool, key any) ([]byte, error)
}

var muSigner2DB sync.RWMutex
var signer2DB = make(map[jwa.SignatureAlgorithm]Signer2)

func RegisterSigner2(alg jwa.SignatureAlgorithm, signer Signer2) {
	muSigner2DB.Lock()
	signer2DB[alg] = signer
	muSigner2DB.Unlock()
}

type SignerFactory interface {
	Create() (Signer, error)
}
type SignerFactoryFn func() (Signer, error)

func (fn SignerFactoryFn) Create() (Signer, error) {
	return fn()
}

var muSignerDB sync.RWMutex
var signerDB = make(map[jwa.SignatureAlgorithm]SignerFactory)

// RegisterSigner is used to register a factory object that creates
// Signer objects based on the given algorithm. Previous object instantiated
// by the factory is discarded.
//
// For example, if you would like to provide a custom signer for
// jwa.EdDSA, use this function to register a `SignerFactory`
// (probably in your `init()`)
//
// Unlike the `UnregisterSigner` function, this function automatically
// calls `jwa.RegisterSignatureAlgorithm` to register the algorithm
// in this module's algorithm database.
func RegisterSigner(alg jwa.SignatureAlgorithm, f SignerFactory) {
	fmt.Println("RegisterSigner", alg)
	jwa.RegisterSignatureAlgorithm(alg)
	muSignerDB.Lock()
	signerDB[alg] = f
	muSignerDB.Unlock()

	// Remove previous signer, if there was one
	removeSigner(alg)
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
	muSignerDB.Lock()
	delete(signerDB, alg)
	muSignerDB.Unlock()
	// Remove previous signer
	removeSigner(alg)
}

func init() {
	for _, alg := range []jwa.SignatureAlgorithm{jwa.ES256(), jwa.ES384(), jwa.ES512(), jwa.ES256K()} {
		RegisterSigner(alg, func(alg jwa.SignatureAlgorithm) SignerFactory {
			return SignerFactoryFn(func() (Signer, error) {
				return newECDSASigner(alg), nil
			})
		}(alg))
	}

	RegisterSigner(jwa.EdDSA(), SignerFactoryFn(func() (Signer, error) {
		return newEdDSASigner(), nil
	}))
}

// NewSigner creates a signer that signs payloads using the given signature algorithm.
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
