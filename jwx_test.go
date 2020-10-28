package jwx_test

import (
	"context"
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx"
	"github.com/lestrrat-go/jwx/internal/jose"
	"github.com/lestrrat-go/jwx/internal/json"
	"github.com/lestrrat-go/jwx/internal/jwxtest"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

type jsonUnmarshalWrapper struct {
	buf []byte
}

func (w jsonUnmarshalWrapper) Decode(v interface{}) error {
	return json.Unmarshal(w.buf, v)
}

func TestDecoderSetting(t *testing.T) {
	const src = `{"foo": 1}`

	for _, useNumber := range []bool{true, false} {
		useNumber := useNumber
		t.Run(fmt.Sprintf("jwx.WithUseNumber(%t)", useNumber), func(t *testing.T) {
			if useNumber {
				jwx.DecoderSettings(jwx.WithUseNumber(useNumber))
				t.Cleanup(func() {
					jwx.DecoderSettings(jwx.WithUseNumber(false))
				})
			}

			// json.NewDecoder must be called AFTER the above jwx.DecoderSettings call
			decoders := []struct {
				Name    string
				Decoder interface{ Decode(interface{}) error }
			}{
				{Name: "Decoder", Decoder: json.NewDecoder(strings.NewReader(src))},
				{Name: "Unmarshal", Decoder: jsonUnmarshalWrapper{buf: []byte(src)}},
			}

			for _, tc := range decoders {
				tc := tc
				t.Run(tc.Name, func(t *testing.T) {
					var m map[string]interface{}
					if !assert.NoError(t, tc.Decoder.Decode(&m), `Decode should succeed`) {
						return
					}

					v, ok := m["foo"]
					if !assert.True(t, ok, `m["foo"] should exist`) {
						return
					}

					if useNumber {
						if !assert.Equal(t, json.Number("1"), v, `v should be a json.Number object`) {
							return
						}
					} else {
						if !assert.Equal(t, float64(1), v, `v should be a float64`) {
							return
						}
					}
				})
			}
		})
	}
}

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

	if !jose.Available() {
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
				keyfile, cleanup, err := jose.GenerateJwk(ctx, t, tc.Template)
				if !assert.NoError(t, err, `jose.GenerateJwk should succeed`) {
					return
				}
				defer cleanup()

				webkey, err := jwxtest.ParseJwkFile(ctx, keyfile)
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
		t.Run("ECDH", func(t *testing.T) {
			t.Run("jose -> jwx", func(t *testing.T) {
				keyfile, jwkcleanup, err := jose.GenerateJwk(ctx, t, `{"alg": "ECDH-ES"}`)
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

				payload, err := jwxtest.DecryptJweFile(ctx, cryptfile, jwa.ECDH_ES, keyfile)
				if !assert.NoError(t, err, `decryptFile.DecryptJwe should succeed`) {
					jwxtest.DumpFile(t, cryptfile)
					return
				}

				if !assert.Equal(t, expected, payload, `decrypted payloads should match`) {
					return
				}
			})
			t.Run("jwx -> jose", func(t *testing.T) {
				kfile, kcleanup, kerr := jwxtest.ECDSAPrivateKeyFile()
				if !assert.NoError(t, kerr, `jwxtest.ECDSAPrivateKeyFile should succeed`) {
					return
				}
				defer kcleanup()

				expected := []byte("hi")

				cryptfile, cleanup, err := jwxtest.EncryptJweFile(ctx, expected, jwa.ECDH_ES, kfile, jwa.A128GCM, jwa.NoCompress)
				if !assert.NoError(t, err, `jwxtest.EncryptJweFile should succeed`) {
					return
				}
				defer cleanup()

				payload, err := jose.DecryptJwe(ctx, t, cryptfile, kfile)
				if !assert.NoError(t, err, `jose.DecryptJwe should succeed`) {
					return
				}

				if !assert.Equal(t, expected, payload, `decrypted payloads should match`) {
					return
				}
			})
		})
	})
}
