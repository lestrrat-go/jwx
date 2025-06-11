package jws

import (
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws/legacy"
)

func init() {
	for _, alg := range []jwa.SignatureAlgorithm{jwa.HS256(), jwa.HS384(), jwa.HS512()} {
		RegisterSigner(alg, func(alg jwa.SignatureAlgorithm) SignerFactory {
			return SignerFactoryFn(func() (Signer, error) {
				return legacy.NewHMACSigner(alg), nil
			})
		}(alg))
		RegisterVerifier(alg, func(alg jwa.SignatureAlgorithm) VerifierFactory {
			return VerifierFactoryFn(func() (Verifier, error) {
				return legacy.NewHMACVerifier(alg), nil
			})
		}(alg))
	}

	for _, alg := range []jwa.SignatureAlgorithm{jwa.RS256(), jwa.RS384(), jwa.RS512(), jwa.PS256(), jwa.PS384(), jwa.PS512()} {
		RegisterSigner(alg, func(alg jwa.SignatureAlgorithm) SignerFactory {
			return SignerFactoryFn(func() (Signer, error) {
				return legacy.NewRSASigner(alg), nil
			})
		}(alg))
		RegisterVerifier(alg, func(alg jwa.SignatureAlgorithm) VerifierFactory {
			return VerifierFactoryFn(func() (Verifier, error) {
				return legacy.NewRSAVerifier(alg), nil
			})
		}(alg))
	}

}
