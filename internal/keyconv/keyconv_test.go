package keyconv_test

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/lestrrat-go/jwx/v3/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v3/internal/keyconv"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"
)

func TestKeyconv(t *testing.T) {
	t.Run("RSA", func(t *testing.T) {
		key, err := jwxtest.GenerateRsaKey()
		require.NoError(t, err, `rsa.GenerateKey should succeed`)
		t.Run("PrivateKey", func(t *testing.T) {
			jwkKey, _ := jwk.Import[jwk.Key](key)
			testcases := []struct {
				Src   any
				Error bool
			}{
				{Src: key},
				{Src: *key},
				{Src: jwkKey},
				{Src: struct{}{}, Error: true},
			}

			for _, tc := range testcases {
				t.Run("Convert to *rsa.PrivateKey", func(t *testing.T) {
					dst, err := keyconv.KeyAs[*rsa.PrivateKey](tc.Src)
					if tc.Error {
						require.Error(t, err, `keyconv.KeyAs[*rsa.PrivateKey] should fail`)
					} else {
						require.NoError(t, err, `keyconv.KeyAs[*rsa.PrivateKey] should succeed`)
						// Reset precomputed values; they will be computed as necessary,
						// and their values are not necessarily stable across runs
						key.Precomputed = rsa.PrecomputedValues{}
						dst.Precomputed = rsa.PrecomputedValues{}
						require.Equal(t, key, dst, `keyconv.KeyAs[*rsa.PrivateKey] should produce same value`)
					}
				})
			}
		})
		t.Run("PublicKey", func(t *testing.T) {
			pubkey := &key.PublicKey
			jwkKey, _ := jwk.Import[jwk.Key](pubkey)
			testcases := []struct {
				Src   any
				Error bool
			}{
				{Src: pubkey},
				{Src: *pubkey},
				{Src: jwkKey},
				{Src: struct{}{}, Error: true},
			}

			for _, tc := range testcases {
				t.Run("Convert to *rsa.PublicKey", func(t *testing.T) {
					dst, err := keyconv.RSAPublicKey(tc.Src)
					if tc.Error {
						require.Error(t, err, `keyconv.RSAPublicKey should fail`)
					} else {
						require.NoError(t, err, `keyconv.RSAPublicKey should succeed`)
						require.Equal(t, pubkey, dst, `keyconv.RSAPublicKey should produce same value`)
					}
				})
			}
		})
	})
	t.Run("ECDSA", func(t *testing.T) {
		key, err := jwxtest.GenerateEcdsaKey(jwa.P521())
		require.NoError(t, err, `ecdsa.GenerateKey should succeed`)

		t.Run("PrivateKey", func(t *testing.T) {
			jwkKey, _ := jwk.Import[jwk.Key](key)
			testcases := []struct {
				Src   any
				Error bool
			}{
				{Src: key},
				{Src: *key},
				{Src: jwkKey},
				{Src: struct{}{}, Error: true},
			}

			for _, tc := range testcases {
				t.Run("Convert to *ecdsa.PrivateKey", func(t *testing.T) {
					dst, err := keyconv.KeyAs[*ecdsa.PrivateKey](tc.Src)
					if tc.Error {
						require.Error(t, err, `keyconv.KeyAs[*ecdsa.PrivateKey] should fail`)
					} else {
						require.NoError(t, err, `keyconv.KeyAs[*ecdsa.PrivateKey] should succeed`)
						require.Equal(t, key, dst, `keyconv.KeyAs[*ecdsa.PrivateKey] should produce same value`)
					}
				})
			}
		})
		t.Run("PublicKey", func(t *testing.T) {
			pubkey := &key.PublicKey
			jwkKey, _ := jwk.Import[jwk.Key](pubkey)
			testcases := []struct {
				Src   any
				Error bool
			}{
				{Src: pubkey},
				{Src: *pubkey},
				{Src: jwkKey},
				{Src: struct{}{}, Error: true},
			}

			for _, tc := range testcases {
				t.Run("Convert to *ecdsa.PublicKey", func(t *testing.T) {
					dst, err := keyconv.ECDSAPublicKey(tc.Src)
					if tc.Error {
						require.Error(t, err, `keyconv.ECDSAPublicKey should fail`)
					} else {
						require.NoError(t, err, `keyconv.ECDSAPublicKey should succeed`)
						require.Equal(t, pubkey, dst, `keyconv.ECDSAPublicKey should produce same value`)
					}
				})
			}
		})
	})
}

func TestECDHToECDSA(t *testing.T) {
	curves := []struct {
		name      string
		ecdhCurve ecdh.Curve
		jwaAlg    jwa.EllipticCurveAlgorithm
	}{
		{"P256", ecdh.P256(), jwa.P256()},
		{"P384", ecdh.P384(), jwa.P384()},
		{"P521", ecdh.P521(), jwa.P521()},
	}

	for _, curve := range curves {
		t.Run(curve.name, func(t *testing.T) {
			// Generate an ECDSA key for comparison
			ecdsaKey, err := jwxtest.GenerateEcdsaKey(curve.jwaAlg)
			require.NoError(t, err, `ecdsa.GenerateKey should succeed`)

			// Convert ECDSA key to ECDH key
			ecdhPrivKey, err := ecdsaKey.ECDH()
			require.NoError(t, err, `ECDSA to ECDH conversion should succeed`)

			ecdhPubKey := ecdhPrivKey.PublicKey()

			t.Run("PrivateKey", func(t *testing.T) {
				testcases := []struct {
					name  string
					src   any
					error bool
				}{
					{"*ecdh.PrivateKey", ecdhPrivKey, false},
					{"invalid type", "not a key", true},
				}

				for _, tc := range testcases {
					t.Run(tc.name, func(t *testing.T) {
						result, err := keyconv.ECDHToECDSA(tc.src)

						if tc.error {
							require.Error(t, err, `ECDHToECDSA should fail for invalid input`)
						} else {
							require.NoError(t, err, `ECDHToECDSA should succeed`)
							require.NotNil(t, result, `result should not be nil`)
							dst := result.(*ecdsa.PrivateKey)

							// Verify the converted key has the same curve
							require.Equal(t, ecdsaKey.Curve, dst.Curve, `curves should match`)

							// Verify the private key values match
							require.Equal(t, ecdsaKey.D, dst.D, `private key values should match`)

							// Verify the public key coordinates match
							require.Equal(t, ecdsaKey.PublicKey.X, dst.PublicKey.X, `X coordinates should match`)
							require.Equal(t, ecdsaKey.PublicKey.Y, dst.PublicKey.Y, `Y coordinates should match`)
						}
					})
				}
			})

			t.Run("PublicKey", func(t *testing.T) {
				testcases := []struct {
					name  string
					src   any
					error bool
				}{
					{"*ecdh.PublicKey", ecdhPubKey, false},
					{"ecdh.PublicKey", *ecdhPubKey, false},
					{"invalid type", "not a key", true},
				}

				for _, tc := range testcases {
					t.Run(tc.name, func(t *testing.T) {
						result, err := keyconv.ECDHToECDSA(tc.src)

						if tc.error {
							require.Error(t, err, `ECDHToECDSA should fail for invalid input`)
						} else {
							require.NoError(t, err, `ECDHToECDSA should succeed`)
							require.NotNil(t, result, `result should not be nil`)
							dst := result.(*ecdsa.PublicKey)

							// Verify the converted key has the same curve
							require.Equal(t, ecdsaKey.PublicKey.Curve, dst.Curve, `curves should match`)

							// Verify the public key coordinates match
							require.Equal(t, ecdsaKey.PublicKey.X, dst.X, `X coordinates should match`)
							require.Equal(t, ecdsaKey.PublicKey.Y, dst.Y, `Y coordinates should match`)
						}
					})
				}
			})

			t.Run("RoundTrip", func(t *testing.T) {
				// Test that ECDSA -> ECDH -> ECDSA produces the same key
				convertedPrivResult, err := keyconv.ECDHToECDSA(ecdhPrivKey)
				require.NoError(t, err, `ECDHToECDSA should succeed`)
				convertedPrivKey := convertedPrivResult.(*ecdsa.PrivateKey)

				convertedPubResult, err := keyconv.ECDHToECDSA(ecdhPubKey)
				require.NoError(t, err, `ECDHToECDSA should succeed`)
				convertedPubKey := convertedPubResult.(*ecdsa.PublicKey)

				// Verify the keys are equivalent
				require.Equal(t, ecdsaKey.D, convertedPrivKey.D, `private key values should match`)
				require.Equal(t, ecdsaKey.PublicKey.X, convertedPrivKey.PublicKey.X, `private key X coordinates should match`)
				require.Equal(t, ecdsaKey.PublicKey.Y, convertedPrivKey.PublicKey.Y, `private key Y coordinates should match`)
				require.Equal(t, ecdsaKey.PublicKey.X, convertedPubKey.X, `public key X coordinates should match`)
				require.Equal(t, ecdsaKey.PublicKey.Y, convertedPubKey.Y, `public key Y coordinates should match`)
			})
		})
	}

	t.Run("UnsupportedCurve", func(t *testing.T) {
		// Create a mock ECDH key with X25519 curve (not supported for ECDSA)
		x25519Key, err := ecdh.X25519().GenerateKey(rand.Reader)
		require.NoError(t, err, `X25519 key generation should succeed`)

		_, err = keyconv.ECDHToECDSA(x25519Key)
		require.Error(t, err, `ECDHToECDSA should fail for unsupported curve`)
		require.Contains(t, err.Error(), "unsupported ECDH curve", `error should mention unsupported curve`)
	})
}
