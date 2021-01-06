package jwx_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx"
	"github.com/lestrrat-go/jwx/internal/jose"
	"github.com/lestrrat-go/jwx/internal/json"
	"github.com/lestrrat-go/jwx/internal/jwxtest"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe"
	"github.com/lestrrat-go/jwx/jwk"
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

// Test compatibility against `jose` tool
func TestJoseCompatibility(t *testing.T) {
	if testing.Short() {
		t.Logf("Skipped during short tests")
		return
	}

	if !jose.Available() {
		t.Logf("`jose` binary not available, skipping tests")
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
		tests := []interopTest{
			{jwa.RSA1_5, jwa.A128GCM},
			{jwa.RSA1_5, jwa.A128CBC_HS256},
			{jwa.RSA1_5, jwa.A256CBC_HS512},
			{jwa.RSA_OAEP, jwa.A128GCM},
			{jwa.RSA_OAEP, jwa.A128CBC_HS256},
			{jwa.RSA_OAEP, jwa.A256CBC_HS512},
			{jwa.RSA_OAEP_256, jwa.A128GCM},
			{jwa.RSA_OAEP_256, jwa.A128CBC_HS256},
			{jwa.RSA_OAEP_256, jwa.A256CBC_HS512},
			{jwa.ECDH_ES, jwa.A128GCM},
			{jwa.ECDH_ES, jwa.A256GCM},
			{jwa.ECDH_ES, jwa.A128CBC_HS256},
			{jwa.ECDH_ES, jwa.A256CBC_HS512},
			{jwa.ECDH_ES_A128KW, jwa.A128GCM},
			{jwa.ECDH_ES_A128KW, jwa.A128CBC_HS256},
			{jwa.ECDH_ES_A256KW, jwa.A256GCM},
			{jwa.ECDH_ES_A256KW, jwa.A256CBC_HS512},
			{jwa.A128KW, jwa.A128GCM},
			{jwa.A128KW, jwa.A128CBC_HS256},
			{jwa.A256KW, jwa.A256GCM},
			{jwa.A256KW, jwa.A256CBC_HS512},
			{jwa.A128GCMKW, jwa.A128GCM},
			{jwa.A128GCMKW, jwa.A128CBC_HS256},
			{jwa.A256GCMKW, jwa.A256GCM},
			{jwa.A256GCMKW, jwa.A256CBC_HS512},
			{jwa.PBES2_HS256_A128KW, jwa.A128GCM},
			{jwa.PBES2_HS256_A128KW, jwa.A128CBC_HS256},
			{jwa.PBES2_HS512_A256KW, jwa.A256GCM},
			{jwa.PBES2_HS512_A256KW, jwa.A256CBC_HS512},
			{jwa.DIRECT, jwa.A128GCM},
			{jwa.DIRECT, jwa.A128CBC_HS256},
			{jwa.DIRECT, jwa.A256GCM},
			{jwa.DIRECT, jwa.A256CBC_HS512},
		}
		for _, test := range tests {
			test := test
			t.Run(fmt.Sprintf("%s-%s", test.alg, test.enc),
				func(t *testing.T) {
					joseInteropTest(ctx, test, t)
				})
		}
	})
}

type interopTest struct {
	alg jwa.KeyEncryptionAlgorithm
	enc jwa.ContentEncryptionAlgorithm
}

func joseInteropTest(ctx context.Context, spec interopTest, t *testing.T) {
	expected := []byte("Lorem ipsum")

	// let jose generate a key file
	alg := spec.alg.String()
	if spec.alg == jwa.DIRECT {
		alg = spec.enc.String()
	}
	joseJwkFile, joseJwkCleanup, err := jose.GenerateJwk(ctx, t, fmt.Sprintf(`{"alg": "%s"}`, alg))
	if !assert.NoError(t, err, `jose.GenerateJwk should succeed`) {
		return
	}
	defer joseJwkCleanup()

	// Load the JWK generated by jose
	jwxJwk, err := jwxtest.ParseJwkFile(ctx, joseJwkFile)
	if !assert.NoError(t, err, `jwxtest.ParseJwkFile should succeed`) {
		return
	}

	t.Run("Parse JWK via jwx", func(t *testing.T) {
		switch spec.alg {
		case jwa.RSA1_5, jwa.RSA_OAEP, jwa.RSA_OAEP_256:
			var rawkey rsa.PrivateKey
			if !assert.NoError(t, jwxJwk.Raw(&rawkey), `jwk.Raw should succeed`) {
				return
			}
		case jwa.ECDH_ES, jwa.ECDH_ES_A128KW, jwa.ECDH_ES_A192KW, jwa.ECDH_ES_A256KW:
			var rawkey ecdsa.PrivateKey
			if !assert.NoError(t, jwxJwk.Raw(&rawkey), `jwk.Raw should succeed`) {
				return
			}
		default:
			var rawkey []byte
			if !assert.NoError(t, jwxJwk.Raw(&rawkey), `jwk.Raw should succeed`) {
				return
			}
		}
	})
	t.Run("Encrypt with jose, Decrypt with jwx", func(t *testing.T) {
		// let jose encrypt payload using the key file
		joseCryptFile, joseCryptCleanup, err := jose.EncryptJwe(ctx, t, expected, spec.alg.String(), joseJwkFile, spec.enc.String(), true)
		if !assert.NoError(t, err, `jose.EncryptJwe should succeed`) {
			return
		}
		defer joseCryptCleanup()

		jwxtest.DumpFile(t, joseCryptFile)

		// let jwx decrypt the jose crypted file
		payload, err := jwxtest.DecryptJweFile(ctx, joseCryptFile, spec.alg, joseJwkFile)
		if !assert.NoError(t, err, `decryptFile.DecryptJwe should succeed`) {
			return
		}

		if !assert.Equal(t, expected, payload, `decrypted payloads should match`) {
			return
		}
	})
	t.Run("Encrypt with jwx, Decrypt with jose", func(t *testing.T) {
		jwxCryptFile, jwxCryptCleanup, err := jwxtest.EncryptJweFile(ctx, expected, spec.alg, joseJwkFile, spec.enc, jwa.NoCompress)
		if !assert.NoError(t, err, `jwxtest.EncryptJweFile should succeed`) {
			return
		}
		defer jwxCryptCleanup()

		payload, err := jose.DecryptJwe(ctx, t, jwxCryptFile, joseJwkFile)
		if !assert.NoError(t, err, `jose.DecryptJwe should succeed`) {
			return
		}

		if !assert.Equal(t, expected, payload, `decrypted payloads should match`) {
			return
		}
	})
}

func TestGHIssue230(t *testing.T) {
	if !jose.Available() {
		t.SkipNow()
	}

	data := "eyJhbGciOiJFQ0RILUVTIiwiY2xldmlzIjp7InBpbiI6InRhbmciLCJ0YW5nIjp7ImFkdiI6eyJrZXlzIjpbeyJhbGciOiJFQ01SIiwiY3J2IjoiUC01MjEiLCJrZXlfb3BzIjpbImRlcml2ZUtleSJdLCJrdHkiOiJFQyIsIngiOiJBZm5tR2xHRTFHRUZ5NEpUT2tGWmo5ZEhEUmdpVE5IeFBST3hpZDZLdm0xVGRFQkZ3bElsSVB6TG5lTjlnb3h6OUVGYmJLM3BoN0tWZS05aVF4MmxhOVNFIiwieSI6IkFmZGFaTVYzVzk1NE14elQxeXF3MWVaRU9xTFFZZnBXSGczMlJvekhyQjBEYmoxWWV3OVFvTDg1M2Y2aUw2REIyRC1nbEcxSFFsb3czdGRNdFhjN1pSY0IifSx7ImFsZyI6IkVTNTEyIiwiY3J2IjoiUC01MjEiLCJrZXlfb3BzIjpbInZlcmlmeSJdLCJrdHkiOiJFQyIsIngiOiJBR0drcXRPZzZqel9pZnhmVnVWQ01CalVySFhCTGtfS2hIb3lKRkU5NmJucTZKZVVHNFNMZnRrZ2FIYk5WT0U4Q3Mwd0JqR0ZkSWxDbnBmak94RGJfbFBoIiwieSI6IkFLU0laT0JYY1Jfa3RkWjZ6T3F3TGI5SEJzai0yYmRMUmw5dFZVbnVlV2N3aXg5X3NiekliSWx0SE9YUGhBTW9yaUlYMWVyNzc4Unh6Vkg5d0FtaUhGa1kifV19LCJ1cmwiOiJodHRwOi8vbG9jYWxob3N0OjM5NDIxIn19LCJlbmMiOiJBMjU2R0NNIiwiZXBrIjp7ImNydiI6IlAtNTIxIiwia3R5IjoiRUMiLCJ4IjoiQUJMUm9sQWotZFdVdzZLSjg2T3J6d1F6RjlGT09URFZBZnNWNkh0OU0zREhyQ045Q0N6dVJ1b3cwbWp6M3BjZnVCaFpYREpfN0dkdzE0LXdneV9fTFNrYyIsInkiOiJBT3NRMzlKZmFQVGhjc2FZTjhSMVBHXzIwYXZxRU1NRl9fM2RHQmI3c1BqNmktNEJORDVMdkZ3cVpJT1l4SS1kVWlvNzkyOWY1YnE0eEdJY0lGWWtlbllxIn0sImtpZCI6ImhlZmVpNzVqMkp4Sko3REZnSDAxUWlOVmlGayJ9..GH3-8v7wfxEsRnki.wns--EIYTRjM3Tb0HyA.EGn2Gq7PnSVvPaMN0oRi5A"

	compactMsg, err := jwe.ParseString(data)
	if !assert.NoError(t, err, `jwe.ParseString should succeed`) {
		return
	}

	formatted, err := jose.FmtJwe(context.TODO(), t, []byte(data))
	if !assert.NoError(t, err, `jose.FmtJwe should succeed`) {
		return
	}

	jsonMsg, err := jwe.Parse(formatted)
	if !assert.NoError(t, err, `jwe.Parse should succeed`) {
		return
	}

	if !assert.Equal(t, compactMsg, jsonMsg, `messages should match`) {
		return
	}
}
