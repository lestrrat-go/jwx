package jwk_test

import (
	"crypto/rand"
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

func rsaPublicJWKFromRaw(t *testing.T, key *rsa.PublicKey) []byte {
	t.Helper()

	return rsaPublicJWK(
		base64.EncodeToString(key.N.Bytes()),
		base64.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	)
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

func TestRSAConfigureCompatibilityKnobs(t *testing.T) {
	t.Run("allow legacy 1024-bit modulus", func(t *testing.T) {
		jwk.Settings(jwk.WithMinRSAModulusBits(1024))
		t.Cleanup(func() {
			jwk.Settings(jwk.WithMinRSAModulusBits(2048))
		})

		raw, err := rsa.GenerateKey(rand.Reader, 1024)
		require.NoError(t, err)

		payload := rsaPublicJWKFromRaw(t, &raw.PublicKey)

		_, err = jwk.ParseKey[jwk.Key](payload)
		require.NoError(t, err)
	})

	t.Run("allow exponent 1 explicitly", func(t *testing.T) {
		jwk.Settings(jwk.WithMinRSAPublicExponent(1))
		t.Cleanup(func() {
			jwk.Settings(jwk.WithMinRSAPublicExponent(3))
		})

		payload := rsaPublicJWK(rfc7638RSAModulus, "AQ")

		_, err := jwk.ParseKey[jwk.Key](payload)
		require.NoError(t, err)
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
