package jwx_test

import (
	"context"
	"crypto/rsa"
	"io/ioutil"
	"os"
	"os/exec"
	"testing"

	"github.com/lestrrat-go/jwx/internal/jose"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func parseJwkFile(_ context.Context, file string) (jwk.Key, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, errors.Wrapf(err, `failed to open file %s`, file)
	}
	defer f.Close()

	buf, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, errors.Wrapf(err, `failed to read from key file %s`, file)
	}

	return jwk.ParseKey(buf)
}

// Test compatibility against `jose` tool
func TestJoseCompatibility(t *testing.T) {
	if testing.Short() {
		t.Logf("Skipped during short tests")
		return
	}

	if _, err := exec.LookPath("jose"); err != nil {
		t.Logf("`jose` binary not availale, skipping tests")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Run("jwk", func(t *testing.T) {
		testcases := []struct {
			Name      string
			Raw       interface{}
			Template  string
			VerifyKey func(context.Context, *testing.T, jwk.Key) bool
		}{
			{
				Name:     "RSA Private Key (256)",
				Raw:      rsa.PrivateKey{},
				Template: `{"alg": "RS256"}`,
			},
			{
				Name:     "RSA Private Key (384)",
				Raw:      rsa.PrivateKey{},
				Template: `{"alg": "RS384"}`,
			},
			{
				Name:     "RSA Private Key (512)",
				Raw:      rsa.PrivateKey{},
				Template: `{"alg": "RS512"}`,
			},
			{
				Name:     "RSA Private Key with Private Parameters",
				Raw:      rsa.PrivateKey{},
				Template: `{"alg": "RS256", "x-jwx": 1234}`,
				VerifyKey: func(ctx context.Context, t *testing.T, key jwk.Key) bool {
					m, err := key.AsMap(ctx)
					if !assert.NoError(t, err, `key.AsMap() should succeed`) {
						return false
					}

					if !assert.Equal(t, float64(1234), m["x-jwx"], `private parameters should match`) {
						return false
					}

					return true
				},
			},
		}

		for _, tc := range testcases {
			tc := tc
			t.Run(tc.Name, func(t *testing.T) {
				keyfile, cleanup, err := jose.GenerateJwk(t, ctx, tc.Template)
				if !assert.NoError(t, err, `jose.GenerateJwk should succeed`) {
					return
				}
				defer cleanup()

				webkey, err := parseJwkFile(ctx, keyfile)
				if !assert.NoError(t, err, `ParseJwkFile should succeed`) {
					return
				}

				if vk := tc.VerifyKey; vk != nil {
					if !vk(ctx, t, webkey) {
						return
					}
				}

				if !assert.NoError(t, webkey.Raw(&tc.Raw), `jwk.Raw should succeed`) {
					return
				}
			})
		}
	})
	t.Run("jwe", func(t *testing.T) {
		t.Run("Encrypt with ECDH key", func(t *testing.T) {
			keyfile, jwkcleanup, err := jose.GenerateJwk(t, ctx, `{"alg": "ECDH-ES"}`)
			if !assert.NoError(t, err, `jose.GenerateJwk should succeed`) {
				return
			}
			defer jwkcleanup()

			expected := []byte("hi")

			cryptfile, jwecleanup, err := jose.EncryptJwe(ctx, t, expected, keyfile)
			if !assert.NoError(t, err, `jose.EncryptJwe should succeed`) {
				return
			}
			defer jwecleanup()

			payload, err := jose.DecryptJwe(ctx, t, cryptfile, keyfile)
			if !assert.NoError(t, err, `jose.DecryptJwe should succeed`) {
				return
			}

			if !assert.Equal(t, expected, payload, `decrypted payloads should match`) {
				return
			}
		})
	})
}
