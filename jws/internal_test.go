package jws

import (
	"testing"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/stretchr/testify/assert"
)

func TestInternal(t *testing.T) {
	algorithms := []jwa.SignatureAlgorithm{
		jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512,
		jwa.ES256, jwa.ES384, jwa.ES512,
		jwa.HS256, jwa.HS384, jwa.HS512,
		jwa.EdDSA,
	}
	testcases := []struct {
		Name       string
		Algorithms []jwa.SignatureAlgorithm
		Signer     SignerFactory
		Verifier   VerifierFactory
	}{
		{
			Name:       "RSA",
			Algorithms: []jwa.SignatureAlgorithm{jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512},
			Signer:     SignerFactoryFn(newRSASigner),
			Verifier:   VerifierFactoryFn(newRSAVerifier),
		},
		{
			Name:       "ECDSA",
			Algorithms: []jwa.SignatureAlgorithm{jwa.ES256, jwa.ES384, jwa.ES512},
			Signer:     SignerFactoryFn(newECDSASigner),
			Verifier:   VerifierFactoryFn(newECDSAVerifier),
		},
		{
			Name:       "HMAC",
			Algorithms: []jwa.SignatureAlgorithm{jwa.HS256, jwa.HS384, jwa.HS512},
			Signer:     SignerFactoryFn(newHMACSigner),
			Verifier:   VerifierFactoryFn(newHMACVerifier),
		},
		{
			Name:       "EdDSA",
			Algorithms: []jwa.SignatureAlgorithm{jwa.EdDSA},
			Signer:     SignerFactoryFn(newEdDSASigner),
			Verifier:   VerifierFactoryFn(newEdDSAVerifier),
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			accepted := make(map[jwa.SignatureAlgorithm]struct{})
			for _, alg := range tc.Algorithms {
				accepted[alg] = struct{}{}
			}

			for _, alg := range algorithms {
				alg := alg
				_, expectPass := accepted[alg]
				t.Run("Signer", func(t *testing.T) {
					_, err := tc.Signer.Create(alg)
					if expectPass {
						if !assert.NoError(t, err, `passing algorithm %s should succeed`, alg) {
							return
						}
					} else {
						if !assert.Error(t, err, `passing algorithm %s should fail`, alg) {
							return
						}
					}
					return
				})
				t.Run("Verifier", func(t *testing.T) {
					_, err := tc.Verifier.Create(alg)
					if expectPass {
						if !assert.NoError(t, err, `passing algorithm %s should succeed`, alg) {
							return
						}
					} else {
						if !assert.Error(t, err, `passing algorithm %s should fail`, alg) {
							return
						}
					}
					return
				})
			}
		})
	}
}
