package jws

import (
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/pkg/errors"
)

type VerifierFactory interface {
	Create(jwa.SignatureAlgorithm) (Verifier, error)
}
type VerifierFactoryFn func(jwa.SignatureAlgorithm) (Verifier, error)

func (fn VerifierFactoryFn) Create(sig jwa.SignatureAlgorithm) (Verifier, error) {
	return fn(sig)
}

var verifierDB map[jwa.SignatureAlgorithm]VerifierFactory

// RegisterVerifier is used to register a factory object that creates
// Verifier objects based on the given algorithm.
//
// For example, if you would like to provide a custom verifier for
// jwa.EdDSA, use this function to register a `VerifierFactory`
// (probably in your `init()`)
func RegisterVerifier(alg jwa.SignatureAlgorithm, f VerifierFactory) {
	verifierDB[alg] = f
}

func init() {
	verifierDB = make(map[jwa.SignatureAlgorithm]VerifierFactory)

	for _, alg := range []jwa.SignatureAlgorithm{jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512} {
		RegisterVerifier(alg, VerifierFactoryFn(newRSAVerifier))
	}

	for _, alg := range []jwa.SignatureAlgorithm{jwa.ES256, jwa.ES384, jwa.ES512} {
		RegisterVerifier(alg, VerifierFactoryFn(newECDSAVerifier))
	}

	for _, alg := range []jwa.SignatureAlgorithm{jwa.HS256, jwa.HS384, jwa.HS512} {
		RegisterVerifier(alg, VerifierFactoryFn(newHMACVerifier))
	}

	RegisterVerifier(jwa.EdDSA, VerifierFactoryFn(newEdDSAVerifier))
}

// NewVerifier creates a verifier that signs payloads using the given signature algorithm.
func NewVerifier(alg jwa.SignatureAlgorithm) (Verifier, error) {
	f, ok := verifierDB[alg]
	if ok {
		return f.Create(alg)
	}
	return nil, errors.Errorf(`unsupported signature algorithm %s`, alg)
}
