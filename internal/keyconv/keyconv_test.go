package keyconv_test

import (
	"crypto/ecdsa"
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
			jwkKey, _ := jwk.Import(key)
			testcases := []struct {
				Src   interface{}
				Error bool
			}{
				{Src: key},
				{Src: *key},
				{Src: jwkKey},
				{Src: struct{}{}, Error: true},
			}

			for _, tc := range testcases {
				t.Run("Assign to rsa.PrivateKey", func(t *testing.T) {
					var dst rsa.PrivateKey
					var checker func(require.TestingT, error, ...interface{})
					if tc.Error {
						checker = require.Error
					} else {
						checker = require.NoError
					}

					checker(t, keyconv.RSAPrivateKey(&dst, tc.Src), `keyconv.RSAPrivateKey should succeed`)
					if !tc.Error {
						// From Go 1.20 on, for purposes of our test, we need the
						// precomputed values as well
						dst.Precompute()
						require.Equal(t, key, &dst, `keyconv.RSAPrivateKey should produce same value`)
					}
				})
				t.Run("Assign to *rsa.PrivateKey", func(t *testing.T) {
					dst := &rsa.PrivateKey{}
					var checker func(require.TestingT, error, ...interface{})
					if tc.Error {
						checker = require.Error
					} else {
						checker = require.NoError
					}

					checker(t, keyconv.RSAPrivateKey(dst, tc.Src), `keyconv.RSAPrivateKey should succeed`)
					if !tc.Error {
						// From Go 1.20 on, for purposes of our test, we need the
						// precomputed values as well
						dst.Precompute()
						require.Equal(t, key, dst, `keyconv.RSAPrivateKey should produce same value`)
					}
				})
			}
		})
		t.Run("PublicKey", func(t *testing.T) {
			pubkey := &key.PublicKey
			jwkKey, _ := jwk.Import(pubkey)
			testcases := []struct {
				Src   interface{}
				Error bool
			}{
				{Src: pubkey},
				{Src: *pubkey},
				{Src: jwkKey},
				{Src: struct{}{}, Error: true},
			}

			for _, tc := range testcases {
				t.Run("Assign to rsa.PublicKey", func(t *testing.T) {
					var dst rsa.PublicKey
					var checker func(require.TestingT, error, ...interface{})
					if tc.Error {
						checker = require.Error
					} else {
						checker = require.NoError
					}

					checker(t, keyconv.RSAPublicKey(&dst, tc.Src), `keyconv.RSAPublicKey should succeed`)
					if !tc.Error {
						require.Equal(t, pubkey, &dst, `keyconv.RSAPublicKey should produce same value`)
					}
				})
				t.Run("Assign to *rsa.PublicKey", func(t *testing.T) {
					dst := &rsa.PublicKey{}
					var checker func(require.TestingT, error, ...interface{})
					if tc.Error {
						checker = require.Error
					} else {
						checker = require.NoError
					}

					checker(t, keyconv.RSAPublicKey(dst, tc.Src), `keyconv.RSAPublicKey should succeed`)
					if !tc.Error {
						require.Equal(t, pubkey, dst, `keyconv.RSAPublicKey should produce same value`)
					}
				})
			}
		})
	})
	t.Run("ECDSA", func(t *testing.T) {
		key, err := jwxtest.GenerateEcdsaKey(jwa.P521)
		require.NoError(t, err, `ecdsa.GenerateKey should succeed`)

		t.Run("PrivateKey", func(t *testing.T) {
			jwkKey, _ := jwk.Import(key)
			testcases := []struct {
				Src   interface{}
				Error bool
			}{
				{Src: key},
				{Src: *key},
				{Src: jwkKey},
				{Src: struct{}{}, Error: true},
			}

			for _, tc := range testcases {
				t.Run("Assign to ecdsa.PrivateKey", func(t *testing.T) {
					var dst ecdsa.PrivateKey
					var checker func(require.TestingT, error, ...interface{})
					if tc.Error {
						checker = require.Error
					} else {
						checker = require.NoError
					}

					checker(t, keyconv.ECDSAPrivateKey(&dst, tc.Src), `keyconv.ECDSAPrivateKey should succeed`)
					if !tc.Error {
						require.Equal(t, key, &dst, `keyconv.ECDSAPrivateKey should produce same value`)
					}
				})
				t.Run("Assign to *ecdsa.PrivateKey", func(t *testing.T) {
					dst := &ecdsa.PrivateKey{}
					var checker func(require.TestingT, error, ...interface{})
					if tc.Error {
						checker = require.Error
					} else {
						checker = require.NoError
					}

					checker(t, keyconv.ECDSAPrivateKey(dst, tc.Src), `keyconv.ECDSAPrivateKey should succeed`)
					if !tc.Error {
						require.Equal(t, key, dst, `keyconv.ECDSAPrivateKey should produce same value`)
					}
				})
			}
		})
		t.Run("PublicKey", func(t *testing.T) {
			pubkey := &key.PublicKey
			jwkKey, _ := jwk.Import(pubkey)
			testcases := []struct {
				Src   interface{}
				Error bool
			}{
				{Src: pubkey},
				{Src: *pubkey},
				{Src: jwkKey},
				{Src: struct{}{}, Error: true},
			}

			for _, tc := range testcases {
				t.Run("Assign to ecdsa.PublicKey", func(t *testing.T) {
					var dst ecdsa.PublicKey
					var checker func(require.TestingT, error, ...interface{})
					if tc.Error {
						checker = require.Error
					} else {
						checker = require.NoError
					}

					checker(t, keyconv.ECDSAPublicKey(&dst, tc.Src), `keyconv.ECDSAPublicKey should succeed`)
					if !tc.Error {
						require.Equal(t, pubkey, &dst, `keyconv.ECDSAPublicKey should produce same value`)
					}
				})
				t.Run("Assign to *ecdsa.PublicKey", func(t *testing.T) {
					dst := &ecdsa.PublicKey{}
					var checker func(require.TestingT, error, ...interface{})
					if tc.Error {
						checker = require.Error
					} else {
						checker = require.NoError
					}

					checker(t, keyconv.ECDSAPublicKey(dst, tc.Src), `keyconv.ECDSAPublicKey should succeed`)
					if !tc.Error {
						require.Equal(t, pubkey, dst, `keyconv.ECDSAPublicKey should produce same value`)
					}
				})
			}
		})
	})
}
