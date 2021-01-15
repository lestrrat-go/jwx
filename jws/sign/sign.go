package sign

import (
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/pkg/errors"
)

type SignerFactory interface {
	Create(jwa.SignatureAlgorithm) (Signer, error)
}
type SignerFactoryFn func(jwa.SignatureAlgorithm) (Signer, error)
func (fn SignerFactoryFn) Create(sig jwa.SignatureAlgorithm) (Signer, error) {
	return fn(sig)
}

var signerDB map[jwa.SignatureAlgorithm]SignerFactory

// Register is used to register a factory object that creates
// Signer objects based on the given algorithm.
func Register(alg jwa.SignatureAlgorithm, f SignerFactory) {
	signerDB[alg] = f
}

func init() {
	signerDB = make(map[jwa.SignatureAlgorithm]SignerFactory)

	for _, alg := range []jwa.SignatureAlgorithm{jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512} {
		Register(alg, SignerFactoryFn(newRSA))
	}

	for _, alg := range []jwa.SignatureAlgorithm{jwa.ES256, jwa.ES384, jwa.ES512} {
		Register(alg, SignerFactoryFn(newECDSA))
	}

	for _, alg := range []jwa.SignatureAlgorithm{jwa.HS256, jwa.HS384, jwa.HS512} {
		Register(alg, SignerFactoryFn(newHMAC))
	}

	Register(jwa.EdDSA, SignerFactory(SignerFactoryFn(func(_ jwa.SignatureAlgorithm) (Signer, error) {
		return newEdDSA()
	})))
}

// New creates a signer that signs payloads using the given signature algorithm.
func New(alg jwa.SignatureAlgorithm) (Signer, error) {
	f, ok := signerDB[alg]
	if ok {
		return f.Create(alg)
	}
	return nil, errors.Errorf(`unsupported signature algorithm %s`, alg)
}
