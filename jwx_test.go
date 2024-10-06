package jwx_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v3"
	"github.com/lestrrat-go/jwx/v3/internal/jose"
	"github.com/lestrrat-go/jwx/v3/internal/json"
	"github.com/lestrrat-go/jwx/v3/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	ourecdsa "github.com/lestrrat-go/jwx/v3/jwk/ecdsa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/stretchr/testify/require"
)

func TestShowBuildInfo(t *testing.T) {
	t.Logf("Running tests using JSON backend => %s\n", json.Engine())
	t.Logf("Available elliptic curves:")
	for _, alg := range ourecdsa.Algorithms() {
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
				t.Run(tc.Name, func(t *testing.T) {
					var m map[string]interface{}
					require.NoError(t, tc.Decoder.Decode(&m), `Decode should succeed`)

					v, ok := m["foo"]
					require.True(t, ok, `m["foo"] should exist`)

					if useNumber {
						require.Equal(t, json.Number("1"), v, `v should be a json.Number object`)
					} else {
						require.Equal(t, float64(1), v, `v should be a float64`)
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
			VerifyKey func(context.Context, *testing.T, jwk.Key)
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
				VerifyKey: func(_ context.Context, t *testing.T, key jwk.Key) {
					var v float64
					require.NoError(t, key.Get(`x-jwx`, &v), `key.Get should succeed`)
					require.Equal(t, float64(1234), v, `private parameters should match`)
				},
			},
		}

		for _, tc := range testcases {
			t.Run(tc.Name, func(t *testing.T) {
				t.Parallel()

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				keyfile, cleanup, err := jose.GenerateJwk(ctx, t, tc.Template)
				require.NoError(t, err, `jose.GenerateJwk should succeed`)
				defer cleanup()

				webkey, err := jwxtest.ParseJwkFile(ctx, keyfile)
				require.NoError(t, err, `ParseJwkFile should succeed`)

				if vk := tc.VerifyKey; vk != nil {
					vk(ctx, t, webkey)
				}

				require.NoError(t, jwk.Export(webkey, &tc.Raw), `jwk.Export should succeed`)
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

		for _, keyenc := range []jwa.KeyEncryptionAlgorithm{jwa.RSA1_5(), jwa.RSA_OAEP(), jwa.RSA_OAEP_256(), jwa.RSA_OAEP_384(), jwa.RSA_OAEP_512()} {
			if !set.Has(keyenc.String()) {
				t.Logf("jose does not support key encryption algorithm %q: skipping", keyenc)
				continue
			}
			for _, contentenc := range []jwa.ContentEncryptionAlgorithm{jwa.A128GCM(), jwa.A128CBC_HS256(), jwa.A256CBC_HS512()} {
				tests = append(tests, interopTest{keyenc, contentenc})
			}
		}

		for _, keyenc := range []jwa.KeyEncryptionAlgorithm{jwa.ECDH_ES(), jwa.ECDH_ES_A128KW(), jwa.A128KW(), jwa.A128GCMKW(), jwa.A256KW(), jwa.A256GCMKW(), jwa.PBES2_HS256_A128KW(), jwa.DIRECT()} {
			if !set.Has(keyenc.String()) {
				t.Logf("jose does not support key encryption algorithm %q: skipping", keyenc)
				continue
			}
			for _, contentenc := range []jwa.ContentEncryptionAlgorithm{jwa.A128GCM(), jwa.A128CBC_HS256()} {
				tests = append(tests, interopTest{keyenc, contentenc})
			}
		}

		for _, keyenc := range []jwa.KeyEncryptionAlgorithm{jwa.ECDH_ES(), jwa.ECDH_ES_A256KW(), jwa.A256KW(), jwa.A256GCMKW(), jwa.PBES2_HS512_A256KW(), jwa.DIRECT()} {
			if !set.Has(keyenc.String()) {
				t.Logf("jose does not support key encryption algorithm %q: skipping", keyenc)
				continue
			}
			for _, contentenc := range []jwa.ContentEncryptionAlgorithm{jwa.A256GCM(), jwa.A256CBC_HS512()} {
				tests = append(tests, interopTest{keyenc, contentenc})
			}
		}

		for _, keyenc := range []jwa.KeyEncryptionAlgorithm{jwa.PBES2_HS384_A192KW()} {
			if !set.Has(keyenc.String()) {
				t.Logf("jose does not support key encryption algorithm %q: skipping", keyenc)
				continue
			}
			for _, contentenc := range []jwa.ContentEncryptionAlgorithm{jwa.A192GCM(), jwa.A192CBC_HS384()} {
				tests = append(tests, interopTest{keyenc, contentenc})
			}
		}

		for _, test := range tests {
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
			jwa.ES256(),
			//jwa.ES256K,
			jwa.ES384(),
			jwa.ES512(),
			//jwa.EdDSA,
			jwa.HS256(),
			jwa.HS384(),
			jwa.HS512(),
			jwa.PS256(),
			jwa.PS384(),
			jwa.PS512(),
			jwa.RS256(),
			jwa.RS384(),
			jwa.RS512(),
		}
		for _, test := range tests {
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
	if spec.alg == jwa.DIRECT() {
		alg = spec.enc.String()
	}
	joseJwkFile, joseJwkCleanup, err := jose.GenerateJwk(ctx, t, fmt.Sprintf(`{"alg": "%s"}`, alg))
	require.NoError(t, err, `jose.GenerateJwk should succeed`)
	defer joseJwkCleanup()

	// Load the JWK generated by jose
	jwxJwk, err := jwxtest.ParseJwkFile(ctx, joseJwkFile)
	require.NoError(t, err, `jwxtest.ParseJwkFile should succeed`)

	t.Run("Parse JWK via jwx", func(t *testing.T) {
		switch spec.alg {
		case jwa.RSA1_5(), jwa.RSA_OAEP(), jwa.RSA_OAEP_256(), jwa.RSA_OAEP_384(), jwa.RSA_OAEP_512():
			var rawkey rsa.PrivateKey
			require.NoError(t, jwk.Export(jwxJwk, &rawkey), `jwk.Export should succeed`)
		case jwa.ECDH_ES(), jwa.ECDH_ES_A128KW(), jwa.ECDH_ES_A192KW(), jwa.ECDH_ES_A256KW():
			var rawkey ecdsa.PrivateKey
			require.NoError(t, jwk.Export(jwxJwk, &rawkey), `jwk.Export should succeed`)
		default:
			var rawkey []byte
			require.NoError(t, jwk.Export(jwxJwk, &rawkey), `jwk.Export should succeed`)
		}
	})
	t.Run("Encrypt with jose, Decrypt with jwx", func(t *testing.T) {
		// let jose encrypt payload using the key file
		joseCryptFile, joseCryptCleanup, err := jose.EncryptJwe(ctx, t, expected, spec.alg.String(), joseJwkFile, spec.enc.String(), true)
		require.NoError(t, err, `jose.EncryptJwe should succeed`)
		defer joseCryptCleanup()

		jwxtest.DumpFile(t, joseCryptFile)

		// let jwx decrypt the jose crypted file
		payload, err := jwxtest.DecryptJweFile(ctx, joseCryptFile, spec.alg, joseJwkFile)
		require.NoError(t, err, `decryptFile.DecryptJwe should succeed`)
		require.Equal(t, expected, payload, `decrypted payloads should match`)
	})
	t.Run("Encrypt with jwx, Decrypt with jose", func(t *testing.T) {
		jwxCryptFile, jwxCryptCleanup, err := jwxtest.EncryptJweFile(ctx, expected, spec.alg, joseJwkFile, spec.enc, jwa.NoCompress())
		require.NoError(t, err, `jwxtest.EncryptJweFile should succeed`)
		defer jwxCryptCleanup()

		payload, err := jose.DecryptJwe(ctx, t, jwxCryptFile, joseJwkFile)
		require.NoError(t, err, `jose.DecryptJwe should succeed`)
		require.Equal(t, expected, payload, `decrypted payloads should match`)
	})
}

func joseJwsInteropTest(ctx context.Context, alg jwa.SignatureAlgorithm, t *testing.T) {
	t.Helper()

	expected := []byte(`{"foo":"bar"}`)

	joseJwkFile, joseJwkCleanup, err := jose.GenerateJwk(ctx, t, fmt.Sprintf(`{"alg": "%s"}`, alg))
	require.NoError(t, err, `jose.GenerateJwk should succeed`)
	defer joseJwkCleanup()

	// Load the JWK generated by jose
	_, err = jwxtest.ParseJwkFile(ctx, joseJwkFile)
	require.NoError(t, err, `jwxtest.ParseJwkFile should succeed`)
	t.Run("Sign with jose, Verify with jwx", func(t *testing.T) {
		// let jose encrypt payload using the key file
		joseCryptFile, joseCryptCleanup, err := jose.SignJws(ctx, t, expected, joseJwkFile, true)
		require.NoError(t, err, `jose.SignJws should succeed`)
		defer joseCryptCleanup()

		jwxtest.DumpFile(t, joseCryptFile)

		// let jwx decrypt the jose crypted file
		payload, err := jwxtest.VerifyJwsFile(ctx, joseCryptFile, alg, joseJwkFile)
		require.NoError(t, err, `jwxtest.VerifyJwsFile should succeed`)
		require.Equal(t, expected, payload, `decrypted payloads should match`)
	})
	t.Run("Sign with jwx, Verify with jose", func(t *testing.T) {
		jwxCryptFile, jwxCryptCleanup, err := jwxtest.SignJwsFile(ctx, expected, alg, joseJwkFile)
		require.NoError(t, err, `jwxtest.SignJwsFile should succeed`)
		defer jwxCryptCleanup()

		payload, err := jose.VerifyJws(ctx, t, jwxCryptFile, joseJwkFile)
		require.NoError(t, err, `jose.VerifyJws should succeed`)
		require.Equal(t, expected, payload, `decrypted payloads should match`)
	})
}

func TestGHIssue230(t *testing.T) {
	t.Parallel()
	if !jose.Available() {
		t.SkipNow()
	}

	data := "eyJhbGciOiJFQ0RILUVTIiwiY2xldmlzIjp7InBpbiI6InRhbmciLCJ0YW5nIjp7ImFkdiI6eyJrZXlzIjpbeyJhbGciOiJFQ01SIiwiY3J2IjoiUC01MjEiLCJrZXlfb3BzIjpbImRlcml2ZUtleSJdLCJrdHkiOiJFQyIsIngiOiJBZm5tR2xHRTFHRUZ5NEpUT2tGWmo5ZEhEUmdpVE5IeFBST3hpZDZLdm0xVGRFQkZ3bElsSVB6TG5lTjlnb3h6OUVGYmJLM3BoN0tWZS05aVF4MmxhOVNFIiwieSI6IkFmZGFaTVYzVzk1NE14elQxeXF3MWVaRU9xTFFZZnBXSGczMlJvekhyQjBEYmoxWWV3OVFvTDg1M2Y2aUw2REIyRC1nbEcxSFFsb3czdGRNdFhjN1pSY0IifSx7ImFsZyI6IkVTNTEyIiwiY3J2IjoiUC01MjEiLCJrZXlfb3BzIjpbInZlcmlmeSJdLCJrdHkiOiJFQyIsIngiOiJBR0drcXRPZzZqel9pZnhmVnVWQ01CalVySFhCTGtfS2hIb3lKRkU5NmJucTZKZVVHNFNMZnRrZ2FIYk5WT0U4Q3Mwd0JqR0ZkSWxDbnBmak94RGJfbFBoIiwieSI6IkFLU0laT0JYY1Jfa3RkWjZ6T3F3TGI5SEJzai0yYmRMUmw5dFZVbnVlV2N3aXg5X3NiekliSWx0SE9YUGhBTW9yaUlYMWVyNzc4Unh6Vkg5d0FtaUhGa1kifV19LCJ1cmwiOiJodHRwOi8vbG9jYWxob3N0OjM5NDIxIn19LCJlbmMiOiJBMjU2R0NNIiwiZXBrIjp7ImNydiI6IlAtNTIxIiwia3R5IjoiRUMiLCJ4IjoiQUJMUm9sQWotZFdVdzZLSjg2T3J6d1F6RjlGT09URFZBZnNWNkh0OU0zREhyQ045Q0N6dVJ1b3cwbWp6M3BjZnVCaFpYREpfN0dkdzE0LXdneV9fTFNrYyIsInkiOiJBT3NRMzlKZmFQVGhjc2FZTjhSMVBHXzIwYXZxRU1NRl9fM2RHQmI3c1BqNmktNEJORDVMdkZ3cVpJT1l4SS1kVWlvNzkyOWY1YnE0eEdJY0lGWWtlbllxIn0sImtpZCI6ImhlZmVpNzVqMkp4Sko3REZnSDAxUWlOVmlGayJ9..GH3-8v7wfxEsRnki.wns--EIYTRjM3Tb0HyA.EGn2Gq7PnSVvPaMN0oRi5A"

	compactMsg, err := jwe.ParseString(data)
	require.NoError(t, err, `jwe.ParseString should succeed`)

	formatted, err := jose.FmtJwe(context.TODO(), t, []byte(data))
	require.NoError(t, err, `jose.FmtJwe should succeed`)

	jsonMsg, err := jwe.Parse(formatted)
	require.NoError(t, err, `jwe.Parse should succeed`)
	require.Equal(t, compactMsg, jsonMsg, `messages should match`)
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
			Source:   []byte(`{"aud":"github.com/lestrrat-go/jwx/v3"}`),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.Name, func(t *testing.T) {
			got := jwx.GuessFormat(tc.Source)
			require.Equal(t, got, tc.Expected, `value of jwx.GuessFormat should match (%s != %s)`, got, tc.Expected)
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
		t.Run(tc.Expected, func(t *testing.T) {
			require.Equal(t, tc.Expected, tc.Value.String(), `stringification should match`)
		})
	}
}

func TestGH996(t *testing.T) {
	ecdsaKey, err := jwxtest.GenerateEcdsaKey(jwa.P256())
	require.NoError(t, err, `jwxtest.GenerateEcdsaKey should succeed`)

	rsaKey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err, `jwxtest.GenerateRsaKey should succeed`)

	okpKey, err := jwxtest.GenerateEd25519Key()
	require.NoError(t, err, `jwxtest.GenerateEd25519Key should succeed`)

	symmetricKey := []byte(`abracadabra`)

	testcases := []struct {
		Name                    string
		Algorithm               jwa.SignatureAlgorithm
		ValidSigningKeys        []interface{}
		InvalidSigningKeys      []interface{}
		ValidVerificationKeys   []interface{}
		InvalidVerificationKeys []interface{}
	}{
		{
			Name:                    `ECDSA`,
			Algorithm:               jwa.ES256(),
			ValidSigningKeys:        []interface{}{ecdsaKey},
			InvalidSigningKeys:      []interface{}{rsaKey, okpKey, symmetricKey},
			ValidVerificationKeys:   []interface{}{ecdsaKey.PublicKey},
			InvalidVerificationKeys: []interface{}{rsaKey.PublicKey, okpKey.Public(), symmetricKey},
		},
		{
			Name:                    `RSA`,
			Algorithm:               jwa.RS256(),
			ValidSigningKeys:        []interface{}{rsaKey},
			InvalidSigningKeys:      []interface{}{ecdsaKey, okpKey, symmetricKey},
			ValidVerificationKeys:   []interface{}{rsaKey.PublicKey},
			InvalidVerificationKeys: []interface{}{ecdsaKey.PublicKey, okpKey.Public(), symmetricKey},
		},
		{
			Name:                    `OKP`,
			Algorithm:               jwa.EdDSA(),
			ValidSigningKeys:        []interface{}{okpKey},
			InvalidSigningKeys:      []interface{}{ecdsaKey, rsaKey, symmetricKey},
			ValidVerificationKeys:   []interface{}{okpKey.Public()},
			InvalidVerificationKeys: []interface{}{ecdsaKey.PublicKey, rsaKey.PublicKey, symmetricKey},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.Name, func(t *testing.T) {
			for _, valid := range tc.ValidSigningKeys {
				t.Run(fmt.Sprintf("Sign Valid(%T)", valid), func(t *testing.T) {
					_, err := jws.Sign([]byte("Lorem Ipsum"), jws.WithKey(tc.Algorithm, valid))
					require.NoError(t, err, `signing with %T should succeed`, valid)
				})
			}

			for _, invalid := range tc.InvalidSigningKeys {
				t.Run(fmt.Sprintf("Sign Invalid(%T)", invalid), func(t *testing.T) {
					_, err := jws.Sign([]byte("Lorem Ipsum"), jws.WithKey(tc.Algorithm, invalid))
					require.Error(t, err, `signing with %T should fail`, invalid)
				})
			}

			signed, err := jws.Sign([]byte("Lorem Ipsum"), jws.WithKey(tc.Algorithm, tc.ValidSigningKeys[0]))
			require.NoError(t, err, `jws.Sign with valid key should succeed`)

			for _, valid := range tc.ValidVerificationKeys {
				t.Run(fmt.Sprintf("Verify Valid(%T)", valid), func(t *testing.T) {
					_, err := jws.Verify(signed, jws.WithKey(tc.Algorithm, valid))
					require.NoError(t, err, `verifying with %T should succeed`, valid)
				})
			}

			for _, invalid := range tc.InvalidVerificationKeys {
				t.Run(fmt.Sprintf("Verify Invalid(%T)", invalid), func(t *testing.T) {
					_, err := jws.Verify(signed, jws.WithKey(tc.Algorithm, invalid))
					require.Error(t, err, `verifying with %T should fail`, invalid)
				})
			}
		})
	}
}

func TestGH1140(t *testing.T) {
	// Using WithUseNumber changes the type of value obtained from the
	// source JSON, which may cause issues
	jwx.DecoderSettings(jwx.WithUseNumber(true))
	t.Cleanup(func() {
		jwx.DecoderSettings(jwx.WithUseNumber(false))
	})
	key, err := jwk.Import([]byte("secure-key"))
	require.NoError(t, err, `jwk.Import should succeed`)

	var encrypted []byte
	encrypted, err = jwe.Encrypt(
		[]byte("test-encryption-payload"),
		jwe.WithKey(jwa.PBES2_HS256_A128KW(), key),
	)
	require.NoError(t, err, `jwe.Encrypt should succeed`)

	_, err = jwe.Decrypt(encrypted, jwe.WithKey(jwa.PBES2_HS256_A128KW(), key))
	require.NoError(t, err, `jwe.Decrypt should succeed`)
}
