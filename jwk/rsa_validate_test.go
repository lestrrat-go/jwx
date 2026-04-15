package jwk_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/base64"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/require"
)

func rsaPublicJWK(n, e string) []byte {
	return []byte(`{"kty":"RSA","n":"` + n + `","e":"` + e + `"}`)
}

func mustBigIntFromBase64(t *testing.T, src string) *big.Int {
	t.Helper()

	body, err := base64.DecodeString(src)
	require.NoError(t, err)
	return new(big.Int).SetBytes(body)
}

func mustRSAPublicPEM(t *testing.T, key *rsa.PublicKey) []byte {
	t.Helper()

	der, err := x509.MarshalPKIXPublicKey(key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})
}

func TestRSAInvalidParametersRejectedOnParse(t *testing.T) {
	t.Run("small modulus", func(t *testing.T) {
		payload := rsaPublicJWK("AQAB", "AQAB")

		_, err := jwk.ParseKey[jwk.Key](payload)
		require.Error(t, err)
		require.True(t, jwk.IsKeyValidationError(err))
		require.Contains(t, err.Error(), "rsa modulus too small")

		_, err = jwk.Parse([]byte(`{"keys":[` + string(payload) + `]}`))
		require.Error(t, err)
		require.Contains(t, err.Error(), "rsa modulus too small")
	})

	t.Run("unsafe exponent", func(t *testing.T) {
		payload := rsaPublicJWK(rfc7638RSAModulus, "AQ")

		_, err := jwk.ParseKey[jwk.Key](payload)
		require.Error(t, err)
		require.True(t, jwk.IsKeyValidationError(err))
		require.Contains(t, err.Error(), "invalid rsa public exponent")
	})
}

func TestRSAImportRejectsInvalidParameters(t *testing.T) {
	t.Run("small modulus", func(t *testing.T) {
		bad := &rsa.PublicKey{
			N: mustBigIntFromBase64(t, "AQAB"),
			E: 65537,
		}

		_, err := jwk.Import[jwk.Key](bad)
		require.Error(t, err)
		require.Contains(t, err.Error(), "rsa modulus too small")
	})

	t.Run("unsafe exponent", func(t *testing.T) {
		bad := &rsa.PublicKey{
			N: mustBigIntFromBase64(t, rfc7638RSAModulus),
			E: 1,
		}

		_, err := jwk.Import[jwk.Key](bad)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid rsa public exponent")
	})
}

func TestRSAPEMImportRunsValidation(t *testing.T) {
	bad := &rsa.PublicKey{
		N: mustBigIntFromBase64(t, "AQAB"),
		E: 65537,
	}

	_, err := jwk.ParseKey[jwk.Key](mustRSAPublicPEM(t, bad), jwk.WithPEM(true))
	require.Error(t, err)
	require.Contains(t, err.Error(), "rsa modulus too small")
}
