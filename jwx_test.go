package jwx_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v2"
	"github.com/lestrrat-go/jwx/v2/internal/ecutil"
	"github.com/lestrrat-go/jwx/v2/internal/jose"
	"github.com/lestrrat-go/jwx/v2/internal/json"
	"github.com/lestrrat-go/jwx/v2/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShowBuildInfo(t *testing.T) {
	t.Logf("Running tests using JSON backend => %s\n", json.Engine())
	t.Logf("Available elliptic curves:")
	for _, alg := range ecutil.AvailableAlgorithms() {
		t.Logf("  %s", alg)
	}
}

type jsonUnmarshalWrapper struct {
	buf []byte
}

func (w jsonUnmarshalWrapper) Decode(v interface{}) error {
	return json.Unmarshal(w.buf, v)
}

func TestDecoderSetting(t *testing.T) {
	// DO NOT MAKE THIS TEST PARALLEL. This test uses features with global side effects
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
	t.Parallel()

	if testing.Short() {
		t.Logf("Skipped during short tests")
		return
	}

	if !jose.Available() {
		t.Logf("`jose` binary not available, skipping tests")
		return
	}

	t.Run("jwk", func(t *testing.T) {
		t.Parallel()
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
				t.Parallel()

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

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
		// For some reason "jose" does not come with RSA-OAEP on some platforms.
		// In order to avoid doing this in an ad-hoc way, we're just going to
		// ask our jose package for the algorithms that it supports, and generate
		// the list dynamically

		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		set, err := jose.Algorithms(ctx, t)
		require.NoError(t, err)

		var tests []interopTest

		for _, keyenc := range []jwa.KeyEncryptionAlgorithm{jwa.RSA1_5, jwa.RSA_OAEP, jwa.RSA_OAEP_256} {
			if !set.Has(keyenc.String()) {
				t.Logf("jose does not support key encryption algorithm %q: skipping", keyenc)
				continue
			}
			for _, contentenc := range []jwa.ContentEncryptionAlgorithm{jwa.A128GCM, jwa.A128CBC_HS256, jwa.A256CBC_HS512} {
				tests = append(tests, interopTest{keyenc, contentenc})
			}
		}

		for _, keyenc := range []jwa.KeyEncryptionAlgorithm{jwa.ECDH_ES, jwa.ECDH_ES_A128KW, jwa.A128KW, jwa.A128GCMKW, jwa.A256KW, jwa.A256GCMKW, jwa.PBES2_HS256_A128KW, jwa.DIRECT} {
			if !set.Has(keyenc.String()) {
				t.Logf("jose does not support key encryption algorithm %q: skipping", keyenc)
				continue
			}
			for _, contentenc := range []jwa.ContentEncryptionAlgorithm{jwa.A128GCM, jwa.A128CBC_HS256} {
				tests = append(tests, interopTest{keyenc, contentenc})
			}
		}

		for _, keyenc := range []jwa.KeyEncryptionAlgorithm{jwa.ECDH_ES, jwa.ECDH_ES_A256KW, jwa.A256KW, jwa.A256GCMKW, jwa.PBES2_HS512_A256KW, jwa.DIRECT} {
			if !set.Has(keyenc.String()) {
				t.Logf("jose does not support key encryption algorithm %q: skipping", keyenc)
				continue
			}
			for _, contentenc := range []jwa.ContentEncryptionAlgorithm{jwa.A256GCM, jwa.A256CBC_HS512} {
				tests = append(tests, interopTest{keyenc, contentenc})
			}
		}

		for _, keyenc := range []jwa.KeyEncryptionAlgorithm{jwa.PBES2_HS384_A192KW} {
			if !set.Has(keyenc.String()) {
				t.Logf("jose does not support key encryption algorithm %q: skipping", keyenc)
				continue
			}
			for _, contentenc := range []jwa.ContentEncryptionAlgorithm{jwa.A192GCM, jwa.A192CBC_HS384} {
				tests = append(tests, interopTest{keyenc, contentenc})
			}
		}

		for _, test := range tests {
			test := test
			t.Run(fmt.Sprintf("%s-%s", test.alg, test.enc), func(t *testing.T) {
				t.Parallel()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				joseInteropTest(ctx, test, t)
			})
		}
	})
	t.Run("jws", func(t *testing.T) {
		t.Parallel()
		tests := []jwa.SignatureAlgorithm{
			jwa.ES256,
			//jwa.ES256K,
			jwa.ES384,
			jwa.ES512,
			//jwa.EdDSA,
			jwa.HS256,
			jwa.HS384,
			jwa.HS512,
			jwa.PS256,
			jwa.PS384,
			jwa.PS512,
			jwa.RS256,
			jwa.RS384,
			jwa.RS512,
		}
		for _, test := range tests {
			test := test
			t.Run(test.String(), func(t *testing.T) {
				t.Parallel()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				joseJwsInteropTest(ctx, test, t)
			})
		}
	})
}

type interopTest struct {
	alg jwa.KeyEncryptionAlgorithm
	enc jwa.ContentEncryptionAlgorithm
}

func joseInteropTest(ctx context.Context, spec interopTest, t *testing.T) {
	t.Helper()

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

func joseJwsInteropTest(ctx context.Context, alg jwa.SignatureAlgorithm, t *testing.T) {
	t.Helper()

	expected := []byte(`{"foo":"bar"}`)

	joseJwkFile, joseJwkCleanup, err := jose.GenerateJwk(ctx, t, fmt.Sprintf(`{"alg": "%s"}`, alg))
	if !assert.NoError(t, err, `jose.GenerateJwk should succeed`) {
		return
	}
	defer joseJwkCleanup()

	// Load the JWK generated by jose
	_, err = jwxtest.ParseJwkFile(ctx, joseJwkFile)
	if !assert.NoError(t, err, `jwxtest.ParseJwkFile should succeed`) {
		return
	}
	t.Run("Sign with jose, Verify with jwx", func(t *testing.T) {
		// let jose encrypt payload using the key file
		joseCryptFile, joseCryptCleanup, err := jose.SignJws(ctx, t, expected, joseJwkFile, true)
		if !assert.NoError(t, err, `jose.SignJws should succeed`) {
			return
		}
		defer joseCryptCleanup()

		jwxtest.DumpFile(t, joseCryptFile)

		// let jwx decrypt the jose crypted file
		payload, err := jwxtest.VerifyJwsFile(ctx, joseCryptFile, alg, joseJwkFile)
		if !assert.NoError(t, err, `jwxtest.VerifyJwsFile should succeed`) {
			return
		}

		if !assert.Equal(t, expected, payload, `decrypted payloads should match`) {
			return
		}
	})
	t.Run("Sign with jwx, Verify with jose", func(t *testing.T) {
		jwxCryptFile, jwxCryptCleanup, err := jwxtest.SignJwsFile(ctx, expected, alg, joseJwkFile)
		if !assert.NoError(t, err, `jwxtest.SignJwsFile should succeed`) {
			return
		}
		defer jwxCryptCleanup()

		payload, err := jose.VerifyJws(ctx, t, jwxCryptFile, joseJwkFile)
		if !assert.NoError(t, err, `jose.VerifyJws should succeed`) {
			return
		}

		if !assert.Equal(t, expected, payload, `decrypted payloads should match`) {
			return
		}
	})
}

func TestGHIssue230(t *testing.T) {
	t.Parallel()
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

func TestGuessFormat(t *testing.T) {
	testcases := []struct {
		Name     string
		Expected jwx.FormatKind
		Source   []byte
	}{
		{
			Name:     "Raw String",
			Expected: jwx.InvalidFormat,
			Source:   []byte(`Hello, World`),
		},
		{
			Name:     "Random JSON Object",
			Expected: jwx.UnknownFormat,
			Source:   []byte(`{"random": "JSON"}`),
		},
		{
			Name:     "Random JSON Array",
			Expected: jwx.InvalidFormat,
			Source:   []byte(`["random", "JSON"]`),
		},
		{
			Name:     "Random Broken JSON",
			Expected: jwx.UnknownFormat,
			Source:   []byte(`{"aud": "foo", "x-customg": "extra semicolon after this string", }`),
		},
		{
			Name:     "JWS",
			Expected: jwx.JWS,
			// from  https://tools.ietf.org/html/rfc7515#appendix-A.1
			Source: []byte(`eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`),
		},
		{
			Name:     "JWE",
			Expected: jwx.JWE,
			Source:   []byte(`eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.XFBoMYUZodetZdvTiFvSkQ`),
		},
		{
			Name:     "JWK",
			Expected: jwx.JWK,
			Source:   []byte(`{"kty":"OKP","crv":"X25519","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"}`),
		},
		{
			Name:     "JWKS",
			Expected: jwx.JWKS,
			Source:   []byte(`{"keys":[{"kty":"OKP","crv":"X25519","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"}]}`),
		},
		{
			Name:     "JWS (JSON)",
			Expected: jwx.JWS,
			Source:   []byte(`{"signatures": [], "payload": ""}`),
		},
		{
			Name:     "JWT",
			Expected: jwx.JWT,
			Source:   []byte(`{"aud":"github.com/lestrrat-go/jwx/v2"}`),
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			got := jwx.GuessFormat(tc.Source)
			if !assert.Equal(t, got, tc.Expected, `value of jwx.GuessFormat should match (%s != %s)`, got, tc.Expected) {
				return
			}
		})
	}
}

func TestFormat(t *testing.T) {
	testcases := []struct {
		Value    jwx.FormatKind
		Expected string
		Error    bool
	}{
		{
			Value:    jwx.UnknownFormat,
			Expected: "UnknownFormat",
		},
		{
			Value:    jwx.JWE,
			Expected: "JWE",
		},
		{
			Value:    jwx.JWS,
			Expected: "JWS",
		},
		{
			Value:    jwx.JWK,
			Expected: "JWK",
		},
		{
			Value:    jwx.JWKS,
			Expected: "JWKS",
		},
		{
			Value:    jwx.JWT,
			Expected: "JWT",
		},
		{
			Value:    jwx.FormatKind(9999999),
			Expected: "FormatKind(9999999)",
		},
	}
	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Expected, func(t *testing.T) {
			if !assert.Equal(t, tc.Expected, tc.Value.String(), `stringification should match`) {
				return
			}
		})
	}
}
