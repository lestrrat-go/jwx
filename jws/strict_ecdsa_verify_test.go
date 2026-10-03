package jws_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/require"
)

func TestStrictECDSAVerification(t *testing.T) {
	t.Parallel()
	strict, ok := jws.WithStrictECDSA(true).(jws.VerifyOption)
	require.True(t, ok, "WithStrictECDSA must support verification as well as signing")

	payload := []byte("strict ECDSA verification")
	algs := []jwa.SignatureAlgorithm{jwa.ES256(), jwa.ES384(), jwa.ES512()}
	curves := []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()}
	for curveIndex, curve := range curves {
		private, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		public, err := jwk.Import[jwk.Key](&private.PublicKey)
		require.NoError(t, err)
		require.NoError(t, public.Set(jwk.KeyIDKey, "test-key"))
		set := jwk.NewSet()
		require.NoError(t, set.AddKey(public))
		for algIndex, alg := range algs {
			t.Run(fmt.Sprintf("%s/%s", alg, curve.Params().Name), func(t *testing.T) {
				t.Parallel()
				match := curveIndex == algIndex
				headers := jws.NewHeaders()
				require.NoError(t, headers.Set(jws.KeyIDKey, "test-key"))
				// The existing permissive signer produces a correctly signed
				// message even for the six non-conforming curve/algorithm pairs.
				for _, serialization := range []jws.SignOption{jws.WithCompact(), jws.WithJSON()} {
					signed, err := jws.Sign(payload, jws.WithKey(alg, private, jws.WithProtectedHeaders(headers)), serialization)
					require.NoError(t, err)
					provider := jws.KeyProviderFunc(func(_ context.Context, sink jws.KeySink, _ *jws.Signature, _ *jws.Message) error {
						sink.Key(alg, public)
						return nil
					})
					for name, keyOption := range map[string]jws.VerifyOption{
						"raw pointer":   jws.WithKey(alg, &private.PublicKey),
						"raw value":     jws.WithKey(alg, private.PublicKey),
						"JWK":           jws.WithKey(alg, public),
						"inferred JWKS": jws.WithKeySet(set, jws.WithInferAlgorithmFromKey(true)),
						"key provider":  jws.WithKeyProvider(provider),
					} {
						t.Run(fmt.Sprintf("%T/%s", serialization, name), func(t *testing.T) {
							verified, err := jws.Verify(signed, keyOption)
							require.NoError(t, err, "default verification must stay permissive")
							require.Equal(t, payload, verified)
							verified, err = jws.Verify(signed, keyOption, strict, jws.WithValidateKey(true))
							if match {
								require.NoError(t, err)
								require.Equal(t, payload, verified)
							} else {
								require.ErrorIs(t, err, jws.VerificationError())
							}
							// Pooled contexts must not retain the strict flag.
							_, err = jws.Verify(signed, keyOption, jws.WithStrictECDSA(false))
							require.NoError(t, err)
						})
					}
				}
				t.Run("streaming detached", func(t *testing.T) {
					signed, err := jws.Sign(nil, jws.WithKey(alg, private), jws.WithDetachedPayloadReader(bytes.NewReader(payload)))
					require.NoError(t, err)
					for _, key := range []any{&private.PublicKey, public} {
						reader := bytes.NewReader(payload)
						_, err := jws.Verify(signed, jws.WithKey(alg, key), strict, jws.WithDetachedPayloadReader(reader))
						if match {
							require.NoError(t, err)
						} else {
							require.ErrorIs(t, err, jws.VerificationError())
							require.Equal(t, len(payload), reader.Len(), "reject before consuming the payload")
						}
					}
				})
			})
		}
	}
}
