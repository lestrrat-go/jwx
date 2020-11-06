package keyconv_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/lestrrat-go/jwx/internal/keyconv"
	"github.com/stretchr/testify/assert"
)

func TestKeyconv(t *testing.T) {
	t.Run("RSA", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if !assert.NoError(t, err, `rsa.GenerateKey should succeed`) {
			return
		}

		t.Run("PrivateKey", func(t *testing.T) {
			testcases := []struct {
				Src   interface{}
				Error bool
			}{
				{Src: key},
				{Src: *key},
				{Src: struct{}{}, Error: true},
			}

			for _, tc := range testcases {
				tc := tc
				t.Run("Assign to rsa.PrivateKey", func(t *testing.T) {
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
						if !assert.Equal(t, key, &dst, `keyconv.RSAPrivateKey should produce same value`) {
							return
						}
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
						if !assert.Equal(t, key, dst, `keyconv.RSAPrivateKey should produce same value`) {
							return
						}
					}
				})
			}
		})
		t.Run("PublicKey", func(t *testing.T) {
			pubkey := &key.PublicKey
			testcases := []struct {
				Src   interface{}
				Error bool
			}{
				{Src: pubkey},
				{Src: *pubkey},
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
		key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if !assert.NoError(t, err, `ecdsa.GenerateKey should succeed`) {
			return
		}

		t.Run("PrivateKey", func(t *testing.T) {
			testcases := []struct {
				Src   interface{}
				Error bool
			}{
				{Src: key},
				{Src: *key},
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
			testcases := []struct {
				Src   interface{}
				Error bool
			}{
				{Src: pubkey},
				{Src: *pubkey},
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
