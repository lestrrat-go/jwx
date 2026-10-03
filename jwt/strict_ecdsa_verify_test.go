package jwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/require"
)

func TestParseWithStrictECDSAVerification(t *testing.T) {
	t.Parallel()
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			t.Parallel()
			private, err := ecdsa.GenerateKey(curve, rand.Reader)
			require.NoError(t, err)
			public, err := jwk.Import[jwk.Key](&private.PublicKey)
			require.NoError(t, err)
			require.NoError(t, public.Set(jwk.AlgorithmKey, jwa.ES256()))
			set := jwk.NewSet()
			require.NoError(t, set.AddKey(public))
			signed, err := jwt.Sign(jwt.New(), jwt.WithKey(jwa.ES256(), private))
			require.NoError(t, err)
			for _, keyOption := range []jwt.ParseOption{
				jwt.WithKey(jwa.ES256(), &private.PublicKey),
				jwt.WithKeySet(set, jws.WithUseDefault(true)),
			} {
				_, err := jwt.Parse(signed, keyOption)
				require.NoError(t, err, "default parsing must stay permissive")
				_, err = jwt.Parse(signed, keyOption, jwt.WithVerifyOption(jws.WithStrictECDSA(true)))
				if curve == elliptic.P256() {
					require.NoError(t, err)
				} else {
					require.ErrorIs(t, err, jws.VerificationError())
				}
				_, err = jwt.Parse(signed, keyOption, jwt.WithVerifyOption(jws.WithStrictECDSA(false)))
				require.NoError(t, err)
			}
		})
	}
}

func TestVerifyOptionDoesNotDisableClaimValidation(t *testing.T) {
	t.Parallel()
	key := []byte("verify-option-claim-validation-test")
	signed, err := jws.Sign([]byte(`{"exp":1}`), jws.WithKey(jwa.HS256(), key))
	require.NoError(t, err)
	_, err = jwt.Parse(signed, jwt.WithKey(jwa.HS256(), key), jwt.WithVerifyOption(jws.WithStrictECDSA(true)))
	require.ErrorIs(t, err, jwt.TokenExpiredError{})
	_, err = jwt.Parse(signed, jwt.WithVerifyOption(jws.WithStrictECDSA(true)))
	require.Error(t, err, "verify options must not replace the required verification key")
	_, err = jwt.Parse(signed, jwt.WithKey(jwa.HS256(), key), jwt.WithVerifyOption(nil))
	require.Error(t, err, "a nil forwarded option must fail without panicking")
}
