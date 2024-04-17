package keyconv_test

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/internal/jwxtest"
	"github.com/lestrrat-go/jwx/internal/keyconv"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyconv(t *testing.T) {
	t.Run("RSA", func(t *testing.T) {
		key, err := jwxtest.GenerateRsaKey()
		if !assert.NoError(t, err, `rsa.GenerateKey should succeed`) {
			return
		}
		t.Run("PrivateKey", func(t *testing.T) {
			jwkKey, _ := jwk.New(key)
			testcases := []struct {
				Src   interface{}
				Error bool
				Name  string
			}{
				{Src: key, Name: "From rsa.PrivateKey"},
				{Src: *key, Name: "From pointer to rsa.PrivateKey"},
				{Src: jwkKey, Name: "From JWK"},
				{Src: struct{}{}, Name: "From invalid value", Error: true},
			}

			for _, tc := range testcases {
				tc := tc
				t.Run(fmt.Sprintf("Assign to rsa.PrivateKey (%s)", tc.Name), func(t *testing.T) {
					var dst rsa.PrivateKey
					var checker func(assert.TestingT, error, ...interface{}) bool
					if tc.Error {
						checker = assert.Error
					} else {
						checker = assert.NoError
					}

					if !checker(t, keyconv.RSAPrivateKey(&dst, tc.Src), `keyconv.RSAPrivateKey should succeed`) {
						return
					}
					if !tc.Error {
						require.True(t, key.Equal(&dst), `keyconv.RSAPrivateKey should produce same value`)
					}
				})
				t.Run("Assign to *rsa.PrivateKey", func(t *testing.T) {
					dst := &rsa.PrivateKey{}
					var checker func(assert.TestingT, error, ...interface{}) bool
					if tc.Error {
						checker = assert.Error
					} else {
						checker = assert.NoError
					}

					if !checker(t, keyconv.RSAPrivateKey(dst, tc.Src), `keyconv.RSAPrivateKey should succeed`) {
						return
					}
					if !tc.Error {
						require.True(t, key.Equal(dst), `keyconv.RSAPrivateKey should produce same value`)
					}
				})
			}
		})
		t.Run("PublicKey", func(t *testing.T) {
			pubkey := &key.PublicKey
			jwkKey, _ := jwk.New(pubkey)
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
				tc := tc
				t.Run("Assign to rsa.PublicKey", func(t *testing.T) {
					var dst rsa.PublicKey
					var checker func(assert.TestingT, error, ...interface{}) bool
					if tc.Error {
						checker = assert.Error
					} else {
						checker = assert.NoError
					}

					if !checker(t, keyconv.RSAPublicKey(&dst, tc.Src), `keyconv.RSAPublicKey should succeed`) {
						return
					}
					if !tc.Error {
						if !assert.Equal(t, pubkey, &dst, `keyconv.RSAPublicKey should produce same value`) {
							return
						}
					}
				})
				t.Run("Assign to *rsa.PublicKey", func(t *testing.T) {
					dst := &rsa.PublicKey{}
					var checker func(assert.TestingT, error, ...interface{}) bool
					if tc.Error {
						checker = assert.Error
					} else {
						checker = assert.NoError
					}

					if !checker(t, keyconv.RSAPublicKey(dst, tc.Src), `keyconv.RSAPublicKey should succeed`) {
						return
					}
					if !tc.Error {
						if !assert.Equal(t, pubkey, dst, `keyconv.RSAPublicKey should produce same value`) {
							return
						}
					}
				})
			}
		})
	})
	t.Run("ECDSA", func(t *testing.T) {
		key, err := jwxtest.GenerateEcdsaKey(jwa.P521)
		if !assert.NoError(t, err, `ecdsa.GenerateKey should succeed`) {
			return
		}

		t.Run("PrivateKey", func(t *testing.T) {
			jwkKey, _ := jwk.New(key)
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
				tc := tc
				t.Run("Assign to ecdsa.PrivateKey", func(t *testing.T) {
					var dst ecdsa.PrivateKey
					var checker func(assert.TestingT, error, ...interface{}) bool
					if tc.Error {
						checker = assert.Error
					} else {
						checker = assert.NoError
					}

					if !checker(t, keyconv.ECDSAPrivateKey(&dst, tc.Src), `keyconv.ECDSAPrivateKey should succeed`) {
						return
					}
					if !tc.Error {
						if !assert.Equal(t, key, &dst, `keyconv.ECDSAPrivateKey should produce same value`) {
							return
						}
					}
				})
				t.Run("Assign to *ecdsa.PrivateKey", func(t *testing.T) {
					dst := &ecdsa.PrivateKey{}
					var checker func(assert.TestingT, error, ...interface{}) bool
					if tc.Error {
						checker = assert.Error
					} else {
						checker = assert.NoError
					}

					if !checker(t, keyconv.ECDSAPrivateKey(dst, tc.Src), `keyconv.ECDSAPrivateKey should succeed`) {
						return
					}
					if !tc.Error {
						if !assert.Equal(t, key, dst, `keyconv.ECDSAPrivateKey should produce same value`) {
							return
						}
					}
				})
			}
		})
		t.Run("PublicKey", func(t *testing.T) {
			pubkey := &key.PublicKey
			jwkKey, _ := jwk.New(pubkey)
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
				tc := tc
				t.Run("Assign to ecdsa.PublicKey", func(t *testing.T) {
					var dst ecdsa.PublicKey
					var checker func(assert.TestingT, error, ...interface{}) bool
					if tc.Error {
						checker = assert.Error
					} else {
						checker = assert.NoError
					}

					if !checker(t, keyconv.ECDSAPublicKey(&dst, tc.Src), `keyconv.ECDSAPublicKey should succeed`) {
						return
					}
					if !tc.Error {
						if !assert.Equal(t, pubkey, &dst, `keyconv.ECDSAPublicKey should produce same value`) {
							return
						}
					}
				})
				t.Run("Assign to *ecdsa.PublicKey", func(t *testing.T) {
					dst := &ecdsa.PublicKey{}
					var checker func(assert.TestingT, error, ...interface{}) bool
					if tc.Error {
						checker = assert.Error
					} else {
						checker = assert.NoError
					}

					if !checker(t, keyconv.ECDSAPublicKey(dst, tc.Src), `keyconv.ECDSAPublicKey should succeed`) {
						return
					}
					if !tc.Error {
						if !assert.Equal(t, pubkey, dst, `keyconv.ECDSAPublicKey should produce same value`) {
							return
						}
					}
				})
			}
		})
	})
}
