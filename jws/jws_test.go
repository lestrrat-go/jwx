package jws_test

import (
	"bufio"
	"bytes"
	"cmp"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/internal/base64"
	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/lestrrat-go/jwx/v4/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v4/internal/tokens"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jws/jwsbb"
	"github.com/stretchr/testify/require"
)

const examplePayload = `{"iss":"joe",` + "\r\n" + ` "exp":1300819380,` + "\r\n" + ` "http://example.com/is_root":true}`
const exampleCompactSerialization = `eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`
const badValue = "%badvalue%"

// ES256K support has been moved to the github.com/jwx-go/es256k extension module.

func TestSanity(t *testing.T) {
	t.Run("sanity: Verify with single key", func(t *testing.T) {
		key, err := jwk.ParseKey([]byte(`{
    "kty": "oct",
    "k": "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
  }`))
		require.NoError(t, err, `jwk.ParseKey should succeed`)
		payload, err := jws.Verify([]byte(exampleCompactSerialization), jws.WithKey(jwa.HS256(), key))
		require.NoError(t, err, `jws.Verify should succeed`)
		require.Equal(t, []byte(examplePayload), payload, `payloads should match`)
	})
	t.Run("sanity: Verification failure", func(t *testing.T) {
		key1, err := jwxtest.GenerateSymmetricJwk()
		require.NoError(t, err, `jwxtest.GenerateSymmetricJwk should succeed`)
		require.NoError(t, key1.Set(jwk.KeyIDKey, "key1"), `key1.Set should succeed`)
		key2, err := jwxtest.GenerateRsaJwk()
		require.NoError(t, err, `jwxtest.GenerateRsaJwk should succeed`)
		require.NoError(t, key2.Set(jwk.KeyIDKey, "key2"), `key2.Set should succeed`)
		key3, err := jwxtest.GenerateEcdsaJwk()
		require.NoError(t, err, `jwxtest.GenerateEcdsaJwk should succeed`)
		require.NoError(t, key3.Set(jwk.KeyIDKey, "key3"), `key3.Set should succeed`)

		payload := []byte(`Lorem Ipsum Dolor Sit Amet`)

		signed, err := jws.Sign(
			payload,
			jws.WithJSON(),
			jws.WithKey(jwa.HS256(), key1),
			jws.WithKey(jwa.RS256(), key2),
			jws.WithKey(jwa.ES256(), key3),
		)
		require.NoError(t, err, `jws.Sign should succeed`)

		t.Run("error type when parse fails", func(t *testing.T) {
			// try to verify a malformed jws message
			_, err = jws.Verify(
				[]byte(`this.is.not.a.ws.message`),
				jws.WithKey(jwa.HS256(), key1),
				jws.WithKey(jwa.RS256(), key2),
				jws.WithKey(jwa.ES256(), key3),
			)
			require.Error(t, err, `jws.Verify should fail`)

			// this should return true because it's an error returned from jws.Verify
			require.True(t, errors.Is(err, jws.VerifyError()), `errors.Is(jws.VerifyError()) should return true`)

			// this should return false because it's a parse error, not something from the verification process
			require.False(t, errors.Is(err, jws.VerificationError()), `errors.Is(jws.VerificationError()) should return false`)

			// this actually should be a parse error
			require.True(t, errors.Is(err, jws.ParseError()), `errors.Is(jws.ParseError()) should return true`)
		})

		t.Run("error type when verification fails", func(t *testing.T) {
			// Create new keys so that verification fails
			key1, err := jwxtest.GenerateSymmetricJwk()
			require.NoError(t, err, `jwxtest.GenerateSymmetricJwk should succeed`)
			require.NoError(t, key1.Set(jwk.KeyIDKey, "key1"), `key1.Set should succeed`)
			key2, err := jwxtest.GenerateRsaJwk()
			require.NoError(t, err, `jwxtest.GenerateRsaJwk should succeed`)
			require.NoError(t, key2.Set(jwk.KeyIDKey, "key2"), `key2.Set should succeed`)
			key3, err := jwxtest.GenerateEcdsaJwk()
			require.NoError(t, err, `jwxtest.GenerateEcdsaJwk should succeed`)
			require.NoError(t, key3.Set(jwk.KeyIDKey, "key3"), `key3.Set should succeed`)

			verified, err := jws.Verify(
				signed,
				jws.WithKey(jwa.HS256(), key1),
				jws.WithKey(jwa.RS256(), key2),
				jws.WithKey(jwa.ES256(), key3),
			)

			require.Error(t, err, `jws.Verify should fail`)
			require.Nil(t, verified, `verified should be nil`)

			// this should return true because it's an error returned from jws.Verify
			require.True(t, errors.Is(err, jws.VerifyError()), `errors.Is(jws.VerifyError()) should return true`)

			// this should also return true because it's an error returned from the verification process
			require.ErrorIs(t, err, jws.VerificationError(), `errors.Is(jws.VerificationError()) should return true (was %T)`, err)
		})
	})
}

func TestParseReader(t *testing.T) {
	t.Parallel()
	t.Run("Empty []byte", func(t *testing.T) {
		t.Parallel()
		_, err := jws.Parse(nil)
		require.Error(t, err, "Parsing an empty byte slice should result in an error")
	})
	t.Run("Empty bytes.Buffer", func(t *testing.T) {
		t.Parallel()
		_, err := jws.ParseReader(&bytes.Buffer{})
		require.Error(t, err, "Parsing an empty buffer should result in an error")
	})
	t.Run("Compact detached payload", func(t *testing.T) {
		t.Parallel()
		split := strings.Split(exampleCompactSerialization, ".")
		incoming := strings.Join([]string{split[0], "", split[2]}, ".")
		_, err := jws.ParseString(incoming)
		require.NoError(t, err, `jws.ParseString should succeed`)
	})
	t.Run("Compact missing header", func(t *testing.T) {
		t.Parallel()
		incoming := strings.Join(
			(strings.Split(
				exampleCompactSerialization,
				".",
			))[:2],
			".",
		)

		for _, useReader := range []bool{true, false} {
			var err error
			if useReader {
				// Force ParseReader() to choose un-optimized path by using bufio.NewReader
				_, err = jws.ParseReader(bufio.NewReader(strings.NewReader(incoming)))
			} else {
				_, err = jws.ParseString(incoming)
			}
			require.Error(t, err, "Parsing compact serialization with less than 3 parts should be an error")
		}
	})
	t.Run("Compact bad header", func(t *testing.T) {
		t.Parallel()
		parts := strings.Split(exampleCompactSerialization, ".")
		parts[0] = badValue
		incoming := strings.Join(parts, ".")

		for _, useReader := range []bool{true, false} {
			var err error
			if useReader {
				_, err = jws.ParseReader(bufio.NewReader(strings.NewReader(incoming)))
			} else {
				_, err = jws.ParseString(incoming)
			}
			require.Error(t, err, "Parsing compact serialization with bad header should be an error")
		}
	})
	t.Run("Compact bad payload", func(t *testing.T) {
		t.Parallel()
		parts := strings.Split(exampleCompactSerialization, ".")
		parts[1] = badValue
		incoming := strings.Join(parts, ".")

		for _, useReader := range []bool{true, false} {
			var err error
			if useReader {
				_, err = jws.ParseReader(bufio.NewReader(strings.NewReader(incoming)))
			} else {
				_, err = jws.ParseString(incoming)
			}
			require.Error(t, err, "Parsing compact serialization with bad payload should be an error")
		}
	})
	t.Run("Compact bad signature", func(t *testing.T) {
		t.Parallel()
		parts := strings.Split(exampleCompactSerialization, ".")
		parts[2] = badValue
		incoming := strings.Join(parts, ".")

		for _, useReader := range []bool{true, false} {
			var err error
			if useReader {
				_, err = jws.ParseReader(bufio.NewReader(strings.NewReader(incoming)))
			} else {
				_, err = jws.ParseString(incoming)
			}
			require.Error(t, err, "Parsing compact serialization with bad signature should be an error")
		}
	})
}

func TestParseCompactEmptySignature(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		Name   string
		Header string
		OK     bool
	}{
		{
			Name:   "SignedAlgorithmRejected",
			Header: `{"alg":"HS256"}`,
		},
		{
			Name:   "MissingAlgorithmRejected",
			Header: `{"typ":"JWT"}`,
		},
		{
			Name:   "NoSignatureAllowed",
			Header: `{"alg":"none"}`,
			OK:     true,
		},
	}

	payload := base64.Encode([]byte("test"))

	for _, tc := range testcases {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			protected := string(base64.Encode([]byte(tc.Header)))
			compact := protected + "." + string(payload) + "."

			msg, err := jws.Parse([]byte(compact))
			if tc.OK {
				require.NoError(t, err, `jws.Parse should succeed`)
				require.Len(t, msg.Signatures(), 1, `message should contain one signature`)
				require.Empty(t, msg.Signatures()[0].Signature(), `signature should be empty`)
			} else {
				require.Error(t, err, `jws.Parse should fail`)
				require.ErrorIs(t, err, jws.ParseError(), `error should match jws.ParseError`)
			}

			msg, err = jws.ParseString(compact)
			if tc.OK {
				require.NoError(t, err, `jws.ParseString should succeed`)
				require.Len(t, msg.Signatures(), 1, `message should contain one signature`)
				require.Empty(t, msg.Signatures()[0].Signature(), `signature should be empty`)
			} else {
				require.Error(t, err, `jws.ParseString should fail`)
				require.ErrorIs(t, err, jws.ParseError(), `error should match jws.ParseError`)
			}

			msg, err = jws.ParseReader(bufio.NewReader(strings.NewReader(compact)))
			if tc.OK {
				require.NoError(t, err, `jws.ParseReader should succeed`)
				require.Len(t, msg.Signatures(), 1, `message should contain one signature`)
				require.Empty(t, msg.Signatures()[0].Signature(), `signature should be empty`)
			} else {
				require.Error(t, err, `jws.ParseReader should fail`)
				require.ErrorIs(t, err, jws.ParseError(), `error should match jws.ParseError`)
			}
		})
	}
}

type dummyCryptoSigner struct {
	raw crypto.Signer
}

func (s *dummyCryptoSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.raw.Sign(rand, digest, opts)
}

func (s *dummyCryptoSigner) Public() crypto.PublicKey {
	return s.raw.Public()
}

var _ crypto.Signer = &dummyCryptoSigner{}

type dummyECDSACryptoSigner struct {
	raw *ecdsa.PrivateKey
}

func (es *dummyECDSACryptoSigner) Public() crypto.PublicKey {
	return es.raw.Public()
}

func (es *dummyECDSACryptoSigner) Sign(rand io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	// The implementation is the same as ecdsaCryptoSigner.
	// This is just here to test the interface conversion
	r, s, err := ecdsa.Sign(rand, es.raw, digest)
	if err != nil {
		return nil, fmt.Errorf(`failed to sign payload using ecdsa: %w`, err)
	}

	return asn1.Marshal(struct {
		R *big.Int
		S *big.Int
	}{R: r, S: s})
}

var _ crypto.Signer = &dummyECDSACryptoSigner{}

func testRoundtrip(t *testing.T, payload []byte, alg jwa.SignatureAlgorithm, signKey any, keys map[string]any) {
	jwkKey, err := jwk.Import[jwk.Key](signKey)
	require.NoError(t, err, `jwk.New should succeed`)
	signKeys := []struct {
		Name string
		Key  any
	}{
		{
			Name: "Raw Key",
			Key:  signKey,
		},
		{
			Name: "JWK Key",
			Key:  jwkKey,
		},
	}

	verifyKeys := make(map[string]any)

	maps.Copy(verifyKeys, keys)

	if es, ok := signKey.(*ecdsa.PrivateKey); ok {
		k := &dummyECDSACryptoSigner{raw: es}
		signKeys = append(signKeys, struct {
			Name string
			Key  any
		}{
			Name: "crypto.Signer",
			Key:  k,
		})
		verifyKeys["Verify(crypto.Signer)"] = k
	} else if cs, ok := signKey.(crypto.Signer); ok {
		k := &dummyCryptoSigner{raw: cs}
		signKeys = append(signKeys, struct {
			Name string
			Key  any
		}{
			Name: "crypto.Signer",
			Key:  k,
		})
		verifyKeys["Verify(crypto.Signer)"] = k
	}

	for _, key := range signKeys {
		t.Run(key.Name, func(t *testing.T) {
			signed, err := jws.Sign(payload, jws.WithKey(alg, key.Key))
			require.NoError(t, err, "jws.Sign should succeed")

			parsers := map[string]func([]byte) (*jws.Message, error){
				"ParseReader(io.Reader)": func(b []byte) (*jws.Message, error) { return jws.ParseReader(bufio.NewReader(bytes.NewReader(b))) },
				"Parse([]byte)":          func(b []byte) (*jws.Message, error) { return jws.Parse(b) },
				"ParseString(string)":    func(b []byte) (*jws.Message, error) { return jws.ParseString(string(b)) },
			}
			for name, f := range parsers {
				t.Run(name, func(t *testing.T) {
					t.Parallel()
					m, err := f(signed)
					require.NoError(t, err, "(%s) %s is successful", alg, name)
					require.Equal(t, payload, m.Payload(), "(%s) %s: Payload is decoded", alg, name)
				})
			}

			for name, testKey := range verifyKeys {
				t.Run(name, func(t *testing.T) {
					verified, err := jws.Verify(signed, jws.WithKey(alg, testKey))
					require.NoError(t, err, "(%s) Verify is successful", alg)
					require.Equal(t, payload, verified, "(%s) Verified payload is the same", alg)
				})
			}
		})
	}
}

func TestRoundtrip(t *testing.T) {
	t.Parallel()
	payload := []byte("Lorem ipsum")

	t.Run("HMAC", func(t *testing.T) {
		t.Parallel()
		sharedkey := []byte("Avracadabra")
		jwkKey, _ := jwk.Import[jwk.Key](sharedkey)
		keys := map[string]any{
			"[]byte":  sharedkey,
			"jwk.Key": jwkKey,
		}
		hmacAlgorithms := []jwa.SignatureAlgorithm{jwa.HS256(), jwa.HS384(), jwa.HS512()}
		for _, alg := range hmacAlgorithms {
			t.Run(alg.String(), func(t *testing.T) {
				t.Parallel()
				testRoundtrip(t, payload, alg, sharedkey, keys)
			})
		}
	})
	t.Run("ECDSA", func(t *testing.T) {
		t.Parallel()
		key, err := jwxtest.GenerateEcdsaKey(jwa.P521())
		require.NoError(t, err, "ECDSA key generated")
		jwkKey, _ := jwk.Import[jwk.Key](key.PublicKey)
		keys := map[string]any{
			"Verify(ecdsa.PublicKey)":  key.PublicKey,
			"Verify(*ecdsa.PublicKey)": &key.PublicKey,
			"Verify(jwk.Key)":          jwkKey,
		}
		for _, alg := range []jwa.SignatureAlgorithm{jwa.ES256(), jwa.ES384(), jwa.ES512()} {
			t.Run(alg.String(), func(t *testing.T) {
				t.Parallel()
				testRoundtrip(t, payload, alg, key, keys)
			})
		}
	})
	t.Run("RSA", func(t *testing.T) {
		t.Parallel()
		key, err := jwxtest.GenerateRsaKey()
		require.NoError(t, err, "RSA key generated")
		jwkKey, _ := jwk.Import[jwk.Key](key.PublicKey)
		keys := map[string]any{
			"Verify(rsa.PublicKey)":  key.PublicKey,
			"Verify(*rsa.PublicKey)": &key.PublicKey,
			"Verify(jwk.Key)":        jwkKey,
		}
		for _, alg := range []jwa.SignatureAlgorithm{jwa.RS256(), jwa.RS384(), jwa.RS512(), jwa.PS256(), jwa.PS384(), jwa.PS512()} {
			t.Run(alg.String(), func(t *testing.T) {
				t.Parallel()
				testRoundtrip(t, payload, alg, key, keys)
			})
		}
	})
	t.Run("EdDSA", func(t *testing.T) {
		t.Parallel()
		key, err := jwxtest.GenerateEd25519Key()
		require.NoError(t, err, "ed25519 key generated")
		pubkey := key.Public()
		jwkKey, _ := jwk.Import[jwk.Key](pubkey)
		keys := map[string]any{
			"Verify(ed25519.Public())": pubkey,
			// Meh, this doesn't work
			// "Verify(*ed25519.Public())": &pubkey,
			"Verify(jwk.Key)": jwkKey,
		}
		for _, alg := range []jwa.SignatureAlgorithm{jwa.EdDSA(), jwa.EdDSAEd25519()} {
			t.Run(alg.String(), func(t *testing.T) {
				t.Parallel()
				testRoundtrip(t, payload, alg, key, keys)
			})
		}
	})
}

func TestRFC9864CrossAlgorithmVerify(t *testing.T) {
	t.Parallel()

	key, err := jwxtest.GenerateEd25519Key()
	require.NoError(t, err, "ed25519 key generated")

	payload := []byte("RFC 9864 cross-algorithm test")

	t.Run("sign with EdDSAEd25519, verify with EdDSA", func(t *testing.T) {
		t.Parallel()
		signed, err := jws.Sign(payload, jws.WithKey(jwa.EdDSAEd25519(), key))
		require.NoError(t, err, "signing with EdDSAEd25519 should succeed")

		// The alg header should be "Ed25519"
		msg, err := jws.Parse(signed)
		require.NoError(t, err, "parsing should succeed")
		sigs := msg.Signatures()
		require.Len(t, sigs, 1)
		alg, ok := sigs[0].ProtectedHeaders().Algorithm()
		require.True(t, ok, "algorithm should be present")
		require.Equal(t, jwa.EdDSAEd25519(), alg)

		// Verify with EdDSA should also work (same crypto)
		verified, err := jws.Verify(signed, jws.WithKey(jwa.EdDSA(), key.Public()))
		require.NoError(t, err, "verifying EdDSAEd25519-signed message with EdDSA should succeed")
		require.Equal(t, payload, verified)
	})

	t.Run("sign with EdDSA, verify with EdDSAEd25519", func(t *testing.T) {
		t.Parallel()
		signed, err := jws.Sign(payload, jws.WithKey(jwa.EdDSA(), key))
		require.NoError(t, err, "signing with EdDSA should succeed")

		// Verify with EdDSAEd25519 should also work (same crypto)
		verified, err := jws.Verify(signed, jws.WithKey(jwa.EdDSAEd25519(), key.Public()))
		require.NoError(t, err, "verifying EdDSA-signed message with EdDSAEd25519 should succeed")
		require.Equal(t, payload, verified)
	})
}

func TestSignMulti2(t *testing.T) {
	sharedkey := []byte("Avracadabra")
	payload := []byte("Lorem ipsum")
	hmacAlgorithms := []jwa.SignatureAlgorithm{jwa.HS256(), jwa.HS384(), jwa.HS512()}
	options := make([]jws.SignOption, 0, 1+len(hmacAlgorithms))
	options = append(options, jws.WithJSON())
	for _, alg := range hmacAlgorithms {
		options = append(options, jws.WithKey(alg, sharedkey)) // (signer, sharedkey, nil, nil))
	}
	signed, err := jws.Sign(payload, options...)
	require.NoError(t, err, `jws.Sign with multiple keys should succeed`)

	for _, alg := range hmacAlgorithms {
		m := jws.NewMessage()
		verified, err := jws.Verify(signed, jws.WithKey(alg, sharedkey), jws.WithMessage(m))
		require.NoError(t, err, "Verify succeeded")
		require.Equal(t, payload, verified, "verified payload matches")

		// XXX This actually doesn't really test much, but if there was anything
		// wrong, the process should have failed well before reaching here
		require.Equal(t, payload, m.Payload(), "message payload matches")
	}
}

func TestEncode(t *testing.T) {
	t.Parallel()

	t.Run("UnsecuredCompact", func(t *testing.T) {
		t.Parallel()
		s := `eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.`

		m, err := jws.ParseReader(strings.NewReader(s))
		require.NoError(t, err, "Parsing compact serialization")

		{
			v := map[string]any{}
			require.NoError(t, json.Unmarshal(m.Payload(), &v), "Unmarshal payload")
			require.Equal(t, v["iss"], "joe", "iss matches")
			require.Equal(t, int(v["exp"].(float64)), 1300819380, "exp matches")
			require.Equal(t, v["http://example.com/is_root"], true, "'http://example.com/is_root' matches")
		}

		require.Len(t, m.Signatures(), 1, "There should be 1 signature")

		signatures := m.Signatures()
		algorithm, ok := signatures[0].ProtectedHeaders().Algorithm()
		if !ok || algorithm != jwa.NoSignature() {
			t.Fatal("Algorithm in header does not match")
		}

		require.Empty(t, signatures[0].Signature(), "Signature should be empty")
	})
	t.Run("CompleteJSON", func(t *testing.T) {
		t.Parallel()
		s := `{
    "payload": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
    "signatures":[
      {
        "header": {"kid":"2010-12-29"},
        "protected":"eyJhbGciOiJSUzI1NiJ9",
        "signature": "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"
      },
      {
        "header": {"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},
        "protected":"eyJhbGciOiJFUzI1NiJ9",
        "signature": "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
      }
    ]
  }`

		m, err := jws.ParseReader(strings.NewReader(s))
		require.NoError(t, err, "Unmarshal complete json serialization")
		require.Len(t, m.Signatures(), 2, "There should be 2 signatures")

		sigs := m.LookupSignature("2010-12-29")
		require.Len(t, sigs, 1, "There should be 1 signature with kid = '2010-12-29'")
	})
	t.Run("Protected Header lookup", func(t *testing.T) {
		t.Parallel()
		s := `{
    "payload": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
    "signatures":[
      {
        "header": {"cty":"example"},
        "protected":"eyJhbGciOiJFUzI1NiIsImtpZCI6ImU5YmMwOTdhLWNlNTEtNDAzNi05NTYyLWQyYWRlODgyZGIwZCJ9",
        "signature": "JcLb1udPAV72TayGv6eawZKlIQQ3K1NzB0fU7wwYoFypGxEczdCQU-V9jp4WwY2ueJKYeE4fF6jigB0PdSKR0Q"
      }
    ]
  }`

		// Protected Header is {"alg":"ES256","kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"}
		// This protected header combination forces the parser/unmarshal to go trough the code path to populate and look for protected header fields.
		// The signature is valid.

		m, err := jws.ParseReader(strings.NewReader(s))
		require.NoError(t, err, "Unmarshal complete json serialization")
		require.Len(t, m.Signatures(), 1, "There should be 1 signature")

		sigs := m.LookupSignature("e9bc097a-ce51-4036-9562-d2ade882db0d")
		require.Len(t, sigs, 1, "There should be 1 signature with kid = '2010-12-29'")
	})
	t.Run("FlattenedJSON", func(t *testing.T) {
		t.Parallel()
		s := `{
    "payload": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
    "protected":"eyJhbGciOiJFUzI1NiJ9",
    "header": {
      "kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"
    },
    "signature": "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
  }`

		m, err := jws.ParseReader(strings.NewReader(s))
		require.NoError(t, err, "Parsing flattened json serialization")
		require.Len(t, m.Signatures(), 1, "There should be 1 signature")

		jsonbuf, _ := json.MarshalIndent(m, "", "  ")
		t.Logf("%s", jsonbuf)
	})
	t.Run("SplitCompact", func(t *testing.T) {
		testcases := []struct {
			Name string
			Size int
		}{
			{Name: "Short", Size: 100},
			{Name: "Long", Size: 8000},
		}
		for _, tc := range testcases {
			size := tc.Size
			t.Run(tc.Name, func(t *testing.T) {
				t.Parallel()
				// Create payload with X.Y.Z
				payload := make([]byte, 0, size+1+size+1+size)
				for range size {
					payload = append(payload, 'X')
				}
				payload = append(payload, tokens.Period)
				for range size {
					payload = append(payload, 'Y')
				}
				payload = append(payload, tokens.Period)

				for range size {
					payload = append(payload, 'Y')
				}

				// Test using bytes, reader optimized and non-optimized path
				for _, method := range []int{0, 1, 2} {
					var x, y, z []byte
					var err error
					switch method {
					case 0: // bytes
						x, y, z, err = jwsbb.SplitCompact(payload)
					case 1: // un-optimized io.Reader
						x, y, z, err = jwsbb.SplitCompactReader(bytes.NewReader(payload))
					default: // optimized io.Reader
						x, y, z, err = jwsbb.SplitCompactReader(bufio.NewReader(bytes.NewReader(payload)))
					}
					require.NoError(t, err, "SplitCompact should succeed")
					require.Len(t, x, size, "Length of header")
					require.Len(t, y, size, "Length of payload")
					require.Len(t, z, size, "Length of signature")
				}
			})
		}
	})
}

func TestReadFile(t *testing.T) {
	t.Parallel()

	f, err := os.CreateTemp(t.TempDir(), "test-read-file-*.jws")
	require.NoError(t, err, `io.CreateTemp should succeed`)
	defer f.Close()

	fmt.Fprintf(f, "%s", exampleCompactSerialization)

	_, err = jws.ParseFS(os.DirFS(filepath.Dir(f.Name())), filepath.Base(f.Name()))
	require.NoError(t, err, `jws.ParseFS should succeed`)
}

func TestVerifyNonUniqueKid(t *testing.T) {
	const payload = "Lorem ipsum"
	const kid = "notUniqueKid"
	privateKey, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err, "jwxtest.GenerateJwk should succeed")
	_ = privateKey.Set(jwk.KeyIDKey, kid)
	signed, err := jws.Sign([]byte(payload), jws.WithKey(jwa.RS256(), privateKey))
	require.NoError(t, err, `jws.Sign should succeed`)
	correctKey, _ := jwk.PublicKeyOf(privateKey)
	_ = correctKey.Set(jwk.AlgorithmKey, jwa.RS256())

	makeSet := func(keys ...jwk.Key) jwk.Set {
		set := jwk.NewSet()
		for _, key := range keys {
			_ = set.AddKey(key)
		}
		return set
	}

	testcases := []struct {
		Name string
		Key  func() jwk.Key // Generates the "wrong" key
	}{
		{
			Name: `match 2 keys via same "kid"`,
			Key: func() jwk.Key {
				privateKey, _ := jwxtest.GenerateRsaJwk()
				wrongKey, _ := jwk.PublicKeyOf(privateKey)
				_ = wrongKey.Set(jwk.KeyIDKey, kid)
				_ = wrongKey.Set(jwk.AlgorithmKey, jwa.RS256())
				return wrongKey
			},
		},
		{
			Name: `match 2 keys via same "kid", same key value but different alg`,
			Key: func() jwk.Key {
				wrongKey, _ := correctKey.Clone()
				_ = wrongKey.Set(jwk.KeyIDKey, kid)
				_ = wrongKey.Set(jwk.AlgorithmKey, jwa.RS512())
				return wrongKey
			},
		},
		{
			Name: `match 2 keys via same "kid", same key type but different alg`,
			Key: func() jwk.Key {
				privateKey, _ := jwxtest.GenerateRsaJwk()
				wrongKey, _ := jwk.PublicKeyOf(privateKey)
				_ = wrongKey.Set(jwk.KeyIDKey, kid)
				_ = wrongKey.Set(jwk.AlgorithmKey, jwa.RS512())
				return wrongKey
			},
		},
		{
			Name: `match 2 keys via same "kid" and different key type / alg`,
			Key: func() jwk.Key {
				privateKey, _ := jwxtest.GenerateEcdsaKey(jwa.P256())
				wrongKey, err := jwk.PublicKeyOf(privateKey)
				require.NoError(t, err, `jwk.PublicKeyOf should succeed`)
				_ = wrongKey.Set(jwk.KeyIDKey, kid)
				_ = wrongKey.Set(jwk.AlgorithmKey, jwa.ES384())
				return wrongKey
			},
		},
	}

	for _, tc := range testcases {
		wrongKey, err := tc.Key().Clone()
		require.NoError(t, err, `cloning wrong key should succeed`)
		for _, set := range []jwk.Set{makeSet(wrongKey, correctKey), makeSet(correctKey, wrongKey)} {
			t.Run(tc.Name, func(t *testing.T) {
				// Try matching in different orders
				var usedKey any
				_, err = jws.Verify(signed, jws.WithKeySet(set, jws.WithMultipleKeysPerKeyID(true)), jws.WithKeyUsed(&usedKey))
				require.NoError(t, err, `jws.Verify should succeed`)
				require.Equal(t, correctKey, usedKey)
			})
		}
	}
}

func TestVerifySet(t *testing.T) {
	t.Parallel()
	const payload = "Lorem ipsum"

	makeSet := func(privkey jwk.Key) jwk.Set {
		set := jwk.NewSet()
		k1, err := jwk.Import[jwk.Key]([]byte("abracadabra"))
		require.NoError(t, err, `jwk.Import should succeed`)
		set.AddKey(k1)
		k2, err := jwk.Import[jwk.Key]([]byte("opensesame"))
		require.NoError(t, err, `jwk.Import should succeed`)
		set.AddKey(k2)
		pubkey, err := jwk.PublicKeyOf(privkey)
		require.NoError(t, err, `jwk.PublicKeyOf should succeed`)
		require.NoError(t, pubkey.Set(jwk.AlgorithmKey, jwa.RS256()), `setting algorithm should succeed`)
		set.AddKey(pubkey)
		return set
	}

	for _, useJSON := range []bool{true, false} {
		t.Run(fmt.Sprintf("useJSON=%t", useJSON), func(t *testing.T) {
			t.Parallel()
			t.Run(`match via "alg"`, func(t *testing.T) {
				t.Parallel()
				key, err := jwxtest.GenerateRsaJwk()
				require.NoError(t, err, "jwxtest.GenerateJwk should succeed")

				set := makeSet(key)
				signed, err := jws.Sign([]byte(payload), jws.WithKey(jwa.RS256(), key))
				require.NoError(t, err, `jws.Sign should succeed`)
				if useJSON {
					m, err := jws.Parse(signed)
					require.NoError(t, err, `jws.Parse should succeed`)
					signed, err = json.Marshal(m)
					require.NoError(t, err, `json.Marshal should succeed`)
				}

				var used any
				verified, err := jws.Verify(signed, jws.WithKeySet(set, jws.WithRequireKid(false)), jws.WithKeyUsed(&used))
				require.NoError(t, err, `jws.Verify should succeed`)
				require.Equal(t, []byte(payload), verified, `payload should match`)
				usedKey := used.(jwk.Key)
				expected, _ := jwk.PublicKeyOf(key)
				thumb1, _ := expected.Thumbprint(crypto.SHA1)
				thumb2, _ := usedKey.Thumbprint(crypto.SHA1)
				require.Equal(t, thumb1, thumb2, `keys should match`)
			})
			t.Run(`match via "kid"`, func(t *testing.T) {
				t.Parallel()

				key, err := jwxtest.GenerateRsaJwk()
				require.NoError(t, err, "jwxtest.GenerateJwk should succeed")
				key.Set(jwk.KeyIDKey, `mykey`)

				set := makeSet(key)
				signed, err := jws.Sign([]byte(payload), jws.WithKey(jwa.RS256(), key))
				require.NoError(t, err, `jws.Sign should succeed`)
				if useJSON {
					m, err := jws.Parse(signed)
					require.NoError(t, err, `jws.Parse should succeed`)
					signed, err = json.Marshal(m)
					require.NoError(t, err, `json.Marshal should succeed`)
				}

				var used any
				verified, err := jws.Verify(signed, jws.WithKeySet(set), jws.WithKeyUsed(&used))
				require.NoError(t, err, `jws.Verify should succeed`)
				require.Equal(t, []byte(payload), verified, `payload should match`)
				usedKey := used.(jwk.Key)
				expected, _ := jwk.PublicKeyOf(key)
				thumb1, _ := expected.Thumbprint(crypto.SHA1)
				thumb2, _ := usedKey.Thumbprint(crypto.SHA1)
				require.Equal(t, thumb1, thumb2, `keys should match`)
			})
		})
	}
}

func TestCustomField(t *testing.T) {
	// XXX has global effect!!!
	const rfc3339Key = `x-test-rfc3339`
	const rfc1123Key = `x-test-rfc1123`
	jws.RegisterCustomField[time.Time](rfc3339Key)
	jws.RegisterCustomDecoder(rfc1123Key, jws.CustomDecodeFunc[time.Time](func(data []byte) (time.Time, error) {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return time.Time{}, err
		}
		return time.Parse(time.RFC1123, s)
	}))

	defer jws.UnregisterCustomField(rfc3339Key)
	defer jws.UnregisterCustomField(rfc1123Key)

	expected := time.Date(2015, 11, 4, 5, 12, 52, 0, time.UTC)
	rfc3339bytes, _ := expected.MarshalText() // RFC3339
	rfc1123bytes := expected.Format(time.RFC1123)

	plaintext := []byte("Hello, World!")
	rsakey, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err, `jwxtest.GenerateRsaJwk() should succeed`)

	t.Run("jws.Parse", func(t *testing.T) {
		protected := jws.NewHeaders()
		protected.Set(rfc3339Key, string(rfc3339bytes))
		protected.Set(rfc1123Key, rfc1123bytes)

		encrypted, err := jws.Sign(plaintext, jws.WithKey(jwa.RS256(), rsakey, jws.WithProtectedHeaders(protected)))
		require.NoError(t, err, `jws.Sign should succeed`)
		msg, err := jws.Parse(encrypted)
		require.NoError(t, err, `jws.Parse should succeed`)
		for _, key := range []string{rfc3339Key, rfc1123Key} {
			fieldV, ok := msg.Signatures()[0].ProtectedHeaders().Field(key)
			require.True(t, ok, `msg.Field(%q) should succeed`, key)
			v, ok := fieldV.(time.Time)
			require.True(t, ok, `value should be time.Time`)
			require.Equal(t, expected, v, `values should match`)
		}
	})
	t.Run("json.Unmarshal", func(t *testing.T) {
		protected := jws.NewHeaders()
		protected.Set(rfc3339Key, string(rfc3339bytes))
		protected.Set(rfc1123Key, rfc1123bytes)

		encrypted, err := jws.Sign(plaintext, jws.WithKey(jwa.RS256(), rsakey, jws.WithProtectedHeaders(protected)), jws.WithJSON())
		require.NoError(t, err, `jws.Sign should succeed`)
		msg := jws.NewMessage()
		require.NoError(t, json.Unmarshal(encrypted, msg), `json.Unmarshal should succeed`)

		for _, key := range []string{rfc3339Key, rfc1123Key} {
			fieldV, ok := msg.Signatures()[0].ProtectedHeaders().Field(key)
			require.True(t, ok, `msg.Field(%q) should succeed`, key)
			v, ok := fieldV.(time.Time)
			require.True(t, ok, `value should be time.Time`)
			require.Equal(t, expected, v, `values should match`)
		}
	})

	/*
		// XXX has global effect!!!
		jws.RegisterCustomField(`x-birthday`, time.Time{})
		defer jws.RegisterCustomField(`x-birthday`, nil)

		expected := time.Date(2015, 11, 4, 5, 12, 52, 0, time.UTC)
		bdaybytes, _ := expected.MarshalText() // RFC3339

		payload := "Hello, World!"
		privkey, err := jwxtest.GenerateRsaJwk()
		require.NoError(t, err, `jwxtest.GenerateRsaJwk() should succeed`)

		hdrs := jws.NewHeaders()
		hdrs.Set(`x-birthday`, string(bdaybytes))

		signed, err := jws.Sign([]byte(payload), jws.WithKey(jwa.RS256(), privkey, jws.WithProtectedHeaders(hdrs)))
		require.NoError(t, err, `jws.Sign should succeed`)

		t.Run("jws.Parse + json.Unmarshal", func(t *testing.T) {
			msg, err := jws.Parse(signed)
			require.NoError(t, err, `jws.Parse should succeed`)

			v, ok := msg.Signatures()[0].ProtectedHeaders().Field(`x-birthday`)
			require.True(t, ok, `msg.Signatures()[0].ProtectedHeaders().Field("x-birthday") should succeed`)

			require.Equal(t, expected, v, `values should match`)

			// Create JSON from jws.Message
			buf, err := json.Marshal(msg)
			require.NoError(t, err, `json.Marshal should succeed`)

			var msg2 jws.Message
			require.NoError(t, json.Unmarshal(buf, &msg2), `json.Unmarshal should succeed`)

			v, ok = msg2.Signatures()[0].ProtectedHeaders().Field(`x-birthday`)
			require.True(t, ok, `msg2.Signatures()[0].ProtectedHeaders().Field("x-birthday") should succeed`)

			require.Equal(t, expected, v, `values should match`)
		})
	*/
}

func TestWithMessage(t *testing.T) {
	key, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err, "jwxtest.Generate should succeed")

	const text = "hello, world"
	signed, err := jws.Sign([]byte(text), jws.WithKey(jwa.RS256(), key))
	require.NoError(t, err, `jws.Sign should succeed`)

	m := jws.NewMessage()
	payload, err := jws.Verify(signed, jws.WithKey(jwa.RS256(), key.PublicKey), jws.WithMessage(m))
	require.NoError(t, err, `jws.Verify should succeed`)
	require.Equal(t, payload, []byte(text), `jws.Verify should produce the correct payload`)

	parsed, err := jws.Parse(signed)
	require.NoError(t, err, `jws.Parse should succeed`)

	// The result of using jws.WithMessage should match the result of jws.Parse
	buf1, _ := json.Marshal(m)
	buf2, _ := json.Marshal(parsed)

	require.Equal(t, buf1, buf2, `result of jws.PArse and jws.Verify(..., jws.WithMessage()) should match`)
}

func TestRFC7797(t *testing.T) {
	const keysrc = `{"kty":"oct",
      "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
     }`

	key, err := jwk.ParseKey([]byte(keysrc))
	require.NoError(t, err, `jwk.Parse should succeed`)

	t.Run("Invalid payload when b64 = false and NOT detached", func(t *testing.T) {
		const payload = `$.02`
		hdrs := jws.NewHeaders()
		hdrs.Set("b64", false)
		hdrs.Set("crit", "b64")

		_, err := jws.Sign([]byte(payload), jws.WithKey(jwa.HS256(), key, jws.WithProtectedHeaders(hdrs)))
		require.Error(t, err, `jws.Sign should fail`)
	})
	t.Run("Invalid usage when b64 = false and NOT detached", func(t *testing.T) {
		const payload = `$.02`
		hdrs := jws.NewHeaders()
		hdrs.Set("b64", false)
		hdrs.Set("crit", "b64")

		_, err := jws.Sign([]byte(payload), jws.WithKey(jwa.HS256(), key, jws.WithProtectedHeaders(hdrs)), jws.WithDetachedPayload([]byte(payload)))
		require.Error(t, err, `jws.Sign should fail`)
	})
	t.Run("Valid payload when b64 = false", func(t *testing.T) {
		testcases := []struct {
			Name     string
			Payload  []byte
			Detached bool
		}{
			{
				Name:     `(Detached) payload contains a period`,
				Payload:  []byte(`$.02`),
				Detached: true,
			},
			{
				Name:    `(NOT detached) payload does not contain a period`,
				Payload: []byte(`hell0w0rld`),
			},
		}

		for _, tc := range testcases {
			t.Run(tc.Name, func(t *testing.T) {
				hdrs := jws.NewHeaders()
				hdrs.Set("b64", false)
				hdrs.Set("crit", "b64")

				payload := tc.Payload
				signOptions := []jws.SignOption{jws.WithKey(jwa.HS256(), key, jws.WithProtectedHeaders(hdrs))}
				var verifyOptions []jws.VerifyOption
				verifyOptions = append(verifyOptions, jws.WithKey(jwa.HS256(), key))
				if tc.Detached {
					signOptions = append(signOptions, jws.WithDetachedPayload(payload))
					// WithDetachedPayload auto-declares "b64" for crit
					// validation; no explicit WithCritExtension needed.
					verifyOptions = append(verifyOptions, jws.WithDetachedPayload(payload))
					payload = nil
				} else {
					// In-band b64=false still requires explicit
					// WithCritExtension("b64") under default-strict.
					verifyOptions = append(verifyOptions, jws.WithCritExtension("b64"))
				}
				signed, err := jws.Sign(payload, signOptions...)
				require.NoError(t, err, `jws.Sign should succeed`)

				verified, err := jws.Verify(signed, verifyOptions...)
				require.NoError(t, err, `jws.Verify should succeed`)
				require.Equal(t, tc.Payload, verified, `payload should match`)
			})
		}
	})

	t.Run("Verify", func(t *testing.T) {
		detached := []byte(`$.02`)
		testcases := []struct {
			Name          string
			Input         []byte
			VerifyOptions []jws.VerifyOption
			Error         bool
		}{
			{
				// In-band b64=false: requires explicit WithCritExtension("b64").
				Name: "JSON format",
				VerifyOptions: []jws.VerifyOption{
					jws.WithCritExtension("b64"),
				},
				Input: []byte(`{
      "protected": "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19",
      "payload": "$.02",
      "signature": "A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY"
     }`),
			},
			{
				// Detached: WithDetachedPayload auto-declares "b64".
				Name: "JSON format (detached payload)",
				VerifyOptions: []jws.VerifyOption{
					jws.WithDetachedPayload(detached),
				},
				Input: []byte(`{
      "protected": "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19",
      "signature": "A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY"
     }`),
			},
			{
				// In-band: explicit WithCritExtension("b64") still required.
				// The test expects an error from b64 mismatch across the two
				// signatures, not from crit rejection.
				Name:  "JSON Format (b64 does not match)",
				Error: true,
				VerifyOptions: []jws.VerifyOption{
					jws.WithCritExtension("b64"),
				},
				Input: []byte(`{
					"signatures": [
						{
							"protected": "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19",
				            "signature": "A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY"
						},
						{
							"protected": "eyJhbGciOiJIUzI1NiIsImI2NCI6dHJ1ZSwiY3JpdCI6WyJiNjQiXX0",
							"signature": "6BjugbC8MfrT_yy5WxWVFZrEHVPDtpdsV9u-wbzQDV8"
						}
					],
					"payload":"$.02"
				}`),
			},
			{
				// Detached: WithDetachedPayload auto-declares "b64".
				Name:  "Compact (detached payload)",
				Input: []byte(`eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY`),
				VerifyOptions: []jws.VerifyOption{
					jws.WithDetachedPayload(detached),
				},
			},
		}

		for _, tc := range testcases {
			t.Run(tc.Name, func(t *testing.T) {
				options := tc.VerifyOptions
				options = append(options, jws.WithKey(jwa.HS256(), key))
				payload, err := jws.Verify(tc.Input, options...)
				if tc.Error {
					require.Error(t, err, `jws.Verify should fail`)
					require.True(t, errors.Is(err, jws.VerifyError()), `jws.IsVerifyError should return true`)
					require.False(t, errors.Is(err, jws.VerificationError()), `jws.IsVerifyError should return false`)
				} else {
					require.NoError(t, err, `jws.Verify should succeed`)
					require.Equal(t, detached, payload, `payload should match`)
				}
			})
		}
	})
}

func TestGH485(t *testing.T) {
	const payload = `eyJhIjoiYiJ9`
	const protected = `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImNyaXQiOlsiZXhwIl0sImV4cCI6MCwiaXNzIjoiZm9vIiwibmJmIjowLCJpYXQiOjB9`
	const signature = `qM0CdRcyR4hw03J2ThJDat3Af40U87wVCF3Tp3xsyOg`
	const expected = `{"a":"b"}`
	signed := fmt.Sprintf(`{
    "payload": %q,
    "signatures": [{"protected": %q, "signature": %q}]
}`, payload, protected, signature)

	verified, err := jws.Verify([]byte(signed), jws.WithKey(jwa.HS256(), []byte("secret")), jws.WithCritExtension("exp"))
	require.NoError(t, err, `jws.Verify should succeed`)
	require.Equal(t, expected, string(verified), `verified payload should match`)

	compact := strings.Join([]string{protected, payload, signature}, ".")
	verified, err = jws.Verify([]byte(compact), jws.WithKey(jwa.HS256(), []byte("secret")), jws.WithCritExtension("exp"))
	require.NoError(t, err, `jws.Verify should succeed`)
	require.Equal(t, expected, string(verified), `verified payload should match`)
}

func TestJKU(t *testing.T) {
	key, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err, `jwxtest.GenerateRsaJwk should succeed`)

	key.Set(jwk.KeyIDKey, `my-awesome-key`)

	pubkey, err := jwk.PublicKeyOf(key)
	require.NoError(t, err, `jwk.PublicKeyOf should succeed`)
	set := jwk.NewSet()
	set.AddKey(pubkey)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.MarshalEncode(json.NewEncoder(w), set)
	}))
	defer srv.Close()

	payload := []byte("Lorem Ipsum")

	t.Run("Compact", func(t *testing.T) {
		testcases := []struct {
			Name    string
			Error   bool
			Query   string
			Fetcher func() jwk.Fetcher
		}{
			{
				Name: "Succeeds without explicit allow",
				Fetcher: func() jwk.Fetcher {
					// nil Allow permits every URL — matches
					// jwkfetch.Client's permissive default.
					return &jwxtest.JKUFetcher{Client: srv.Client()}
				},
			},
			{
				Name:  "Rejected by restrictive allow",
				Error: true,
				Fetcher: func() jwk.Fetcher {
					return &jwxtest.JKUFetcher{
						Client: srv.Client(),
						Allow: func(u string) bool {
							return u == `https://github.com/lestrrat-go/jwx/v4`
						},
					}
				},
			},
			// Cache test case moved to ext/jwkfetch
		}

		for _, tc := range testcases {
			t.Run(tc.Name, func(t *testing.T) {
				hdr := jws.NewHeaders()
				u := srv.URL
				if tc.Query != "" {
					u += "?" + tc.Query
				}
				hdr.Set(jws.JWKSetURLKey, u)
				signed, err := jws.Sign(payload, jws.WithKey(jwa.RS256(), key, jws.WithProtectedHeaders(hdr)))
				require.NoError(t, err, `jws.Sign should succeed`)

				var fetcher jwk.Fetcher
				if f := tc.Fetcher; f != nil {
					fetcher = f()
				}
				decoded, err := jws.Verify(signed, jws.WithVerifyAuto(fetcher))
				if tc.Error {
					require.Error(t, err, `jws.Verify should fail`)
				} else {
					require.NoError(t, err, `jws.Verify should succeed`)
					require.Equal(t, payload, decoded, `decoded payload should match`)
				}
			})
		}
	})
	t.Run("JSON", func(t *testing.T) {
		// scenario: create a JSON message, which contains 3 signature entries.
		// 1st and 3rd signatures are valid, but signed using keys that are not
		// present in the JWKS.
		// Only the second signature uses a key found in the JWKS
		keys := make([]jwk.Key, 0, 3)
		for i := range 3 {
			key, err := jwxtest.GenerateRsaJwk()
			require.NoError(t, err, `jwxtest.GenerateRsaJwk should succeed`)
			key.Set(jwk.KeyIDKey, fmt.Sprintf(`used-%d`, i))
			keys = append(keys, key)
		}

		unusedKeys := make([]jwk.Key, 0, 2)
		for i := range 2 {
			key, err := jwxtest.GenerateRsaJwk()
			require.NoError(t, err, `jwxtest.GenerateRsaJwk should succeed`)
			key.Set(jwk.KeyIDKey, fmt.Sprintf(`unused-%d`, i))
			unusedKeys = append(unusedKeys, key)
		}

		// The set should contain unused key, used key, and unused key.
		// ...but they need to be public keys
		set := jwk.NewSet()
		for _, key := range []jwk.Key{unusedKeys[0], keys[1], unusedKeys[1]} {
			pubkey, err := jwk.PublicKeyOf(key)
			require.NoError(t, err, `jwk.PublicKeyOf should succeed`)

			kid, ok := key.KeyID()
			require.True(t, ok, `key ID should be populated`)

			pubkid, ok := pubkey.KeyID()
			require.True(t, ok, `key ID should be populated`)

			require.Equal(t, kid, pubkid, `key ID should be populated`)
			set.AddKey(pubkey)
		}
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			json.MarshalEncode(json.NewEncoder(w), set)
		}))
		defer srv.Close()

		// Sign the payload using the three keys
		signOptions := make([]jws.SignOption, 0, 1+len(keys))
		signOptions = append(signOptions, jws.WithJSON())
		for _, key := range keys {
			hdr := jws.NewHeaders()
			hdr.Set(jws.JWKSetURLKey, srv.URL)
			signOptions = append(signOptions, jws.WithKey(jwa.RS256(), key, jws.WithProtectedHeaders(hdr)))
		}

		signed, err := jws.Sign(payload, signOptions...)
		require.NoError(t, err, `jws.SignMulti should succeed`)

		testcases := []struct {
			Name  string
			Allow func(string) bool // nil = permit all
			Error bool
		}{
			{
				Name: "Succeeds without explicit allow",
				// nil Allow → fetcher permits every URL.
			},
			{
				Name:  "Rejected by restrictive allow",
				Error: true,
				Allow: func(u string) bool {
					return u == `https://github.com/lestrrat-go/jwx/v4`
				},
			},
		}

		for _, tc := range testcases {
			t.Run(tc.Name, func(t *testing.T) {
				m := jws.NewMessage()
				fetcher := &jwxtest.JKUFetcher{
					Client: srv.Client(),
					Allow:  tc.Allow,
				}

				decoded, err := jws.Verify(signed, jws.WithVerifyAuto(fetcher), jws.WithMessage(m))
				if tc.Error {
					require.Error(t, err, `jws.Verify should fail`)
				} else {
					require.NoError(t, err, `jws.Verify should succeed`)
					require.Equal(t, payload, decoded, `decoded payload should match`)
					// XXX This actually doesn't really test much, but if there was anything
					// wrong, the process should have failed well before reaching here
					require.Equal(t, payload, m.Payload(), "message payload matches")
				}
			})
		}
	})
	t.Run("KidNotInJWKS", func(t *testing.T) {
		// Sign with a key whose kid is NOT present in the remote JWKS.
		// The fetched set only contains a key with a different kid.
		// jkuProvider used to return nil in this case, collapsing the
		// failure into a generic "could not verify" error and hiding
		// the root cause from operators. It must now surface an
		// explicit kid-not-found error.
		signerKey, err := jwxtest.GenerateRsaJwk()
		require.NoError(t, err, `jwxtest.GenerateRsaJwk should succeed`)
		require.NoError(t, signerKey.Set(jwk.KeyIDKey, `signer-kid`), `Set kid should succeed`)

		hdr := jws.NewHeaders()
		require.NoError(t, hdr.Set(jws.JWKSetURLKey, srv.URL), `Set jku should succeed`)
		signed, err := jws.Sign(payload, jws.WithKey(jwa.RS256(), signerKey, jws.WithProtectedHeaders(hdr)))
		require.NoError(t, err, `jws.Sign should succeed`)

		_, err = jws.Verify(signed, jws.WithVerifyAuto(&jwxtest.JKUFetcher{Client: srv.Client()}))
		require.Error(t, err, `jws.Verify should fail when jku JWKS has no matching kid`)
		require.Contains(t, err.Error(), `signer-kid`, `error should name the missing kid`)
		require.Contains(t, err.Error(), `not found`, `error should say the kid was not found`)
	})
}

func TestAlgorithmsForKey(t *testing.T) {
	rsaprivkey, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err, `jwxtest.GenerateRsaPrivateKey should succeed`)
	rsapubkey, err := rsaprivkey.PublicKey()
	require.NoError(t, err, `jwk (RSA) PublicKey() should succeed`)

	ecdsaprivkey, err := jwxtest.GenerateEcdsaJwk()
	require.NoError(t, err, `jwxtest.GenerateEcdsaPrivateKey should succeed`)
	ecdsapubkey, err := ecdsaprivkey.PublicKey()
	require.NoError(t, err, `jwk (ECDSA) PublicKey() should succeed`)

	ed25519privkey, err := jwxtest.GenerateEd25519Jwk()
	require.NoError(t, err, `jwxtest.GenerateEd25519Jwk should succeed`)
	ed25519pubkey, err := ed25519privkey.PublicKey()
	require.NoError(t, err, `jwk (Ed25519) PublicKey() should succeed`)

	x25519privkey, err := jwxtest.GenerateX25519Jwk()
	require.NoError(t, err, `jwxtest.GenerateX25519Jwk should succeed`)
	x25519pubkey, err := x25519privkey.PublicKey()
	require.NoError(t, err, `jwk (X25519) PublicKey() should succeed`)

	testcases := []struct {
		Name     string
		Key      any
		Expected []jwa.SignatureAlgorithm
	}{
		{
			Name:     "Octet sequence",
			Key:      []byte("hello"),
			Expected: []jwa.SignatureAlgorithm{jwa.HS256(), jwa.HS384(), jwa.HS512()},
		},
		{
			Name:     "rsa.PublicKey",
			Key:      rsa.PublicKey{},
			Expected: []jwa.SignatureAlgorithm{jwa.RS256(), jwa.RS384(), jwa.RS512(), jwa.PS256(), jwa.PS384(), jwa.PS512()},
		},
		{
			Name:     "*rsa.PublicKey",
			Key:      &rsa.PublicKey{},
			Expected: []jwa.SignatureAlgorithm{jwa.RS256(), jwa.RS384(), jwa.RS512(), jwa.PS256(), jwa.PS384(), jwa.PS512()},
		},
		{
			Name:     "jwk.RSAPublicKey",
			Key:      rsapubkey,
			Expected: []jwa.SignatureAlgorithm{jwa.RS256(), jwa.RS384(), jwa.RS512(), jwa.PS256(), jwa.PS384(), jwa.PS512()},
		},
		{
			Name:     "ecdsa.PublicKey",
			Key:      ecdsa.PublicKey{},
			Expected: []jwa.SignatureAlgorithm{jwa.ES256(), jwa.ES384(), jwa.ES512()},
		},
		{
			Name:     "*ecdsa.PublicKey",
			Key:      &ecdsa.PublicKey{},
			Expected: []jwa.SignatureAlgorithm{jwa.ES256(), jwa.ES384(), jwa.ES512()},
		},
		{
			Name:     "jwk.ECDSAPublicKey",
			Key:      ecdsapubkey,
			Expected: []jwa.SignatureAlgorithm{jwa.ES256(), jwa.ES384(), jwa.ES512()},
		},
		{
			Name:     "rsa.PrivateKey",
			Key:      rsa.PrivateKey{},
			Expected: []jwa.SignatureAlgorithm{jwa.RS256(), jwa.RS384(), jwa.RS512(), jwa.PS256(), jwa.PS384(), jwa.PS512()},
		},
		{
			Name:     "*rsa.PrivateKey",
			Key:      &rsa.PrivateKey{},
			Expected: []jwa.SignatureAlgorithm{jwa.RS256(), jwa.RS384(), jwa.RS512(), jwa.PS256(), jwa.PS384(), jwa.PS512()},
		},
		{
			Name:     "jwk.RSAPrivateKey",
			Key:      rsapubkey,
			Expected: []jwa.SignatureAlgorithm{jwa.RS256(), jwa.RS384(), jwa.RS512(), jwa.PS256(), jwa.PS384(), jwa.PS512()},
		},
		{
			Name:     "ecdsa.PrivateKey",
			Key:      ecdsa.PrivateKey{},
			Expected: []jwa.SignatureAlgorithm{jwa.ES256(), jwa.ES384(), jwa.ES512()},
		},
		{
			Name:     "*ecdsa.PrivateKey",
			Key:      &ecdsa.PrivateKey{},
			Expected: []jwa.SignatureAlgorithm{jwa.ES256(), jwa.ES384(), jwa.ES512()},
		},
		{
			Name:     "jwk.ECDSAPrivateKey",
			Key:      ecdsaprivkey,
			Expected: []jwa.SignatureAlgorithm{jwa.ES256(), jwa.ES384(), jwa.ES512()},
		},
		{
			Name:     "ed25519.PublicKey",
			Key:      ed25519.PublicKey(nil),
			Expected: []jwa.SignatureAlgorithm{jwa.EdDSA(), jwa.EdDSAEd25519()},
		},
		{
			Name:     "jwk.OKPPublicKey (Ed25519)",
			Key:      ed25519pubkey,
			Expected: []jwa.SignatureAlgorithm{jwa.EdDSA(), jwa.EdDSAEd25519()},
		},
		{
			Name:     "jwk.OKPPrivateKey (Ed25519)",
			Key:      ed25519privkey,
			Expected: []jwa.SignatureAlgorithm{jwa.EdDSA(), jwa.EdDSAEd25519()},
		},
		{
			Name:     "jwk.OKPPublicKey (X25519)",
			Key:      x25519pubkey,
			Expected: []jwa.SignatureAlgorithm{jwa.EdDSA()},
		},
		{
			Name:     "jwk.OKPPrivateKey (X25519)",
			Key:      x25519privkey,
			Expected: []jwa.SignatureAlgorithm{jwa.EdDSA()},
		},
	}

	for _, tc := range testcases {
		slices.SortFunc(tc.Expected, func(a, b jwa.SignatureAlgorithm) int {
			return cmp.Compare(a.String(), b.String())
		})
		t.Run(tc.Name, func(t *testing.T) {
			algs, err := jws.AlgorithmsForKey(tc.Key)
			require.NoError(t, err, `jws.AlgorithmsForKey should succeed`)

			slices.SortFunc(algs, func(a, b jwa.SignatureAlgorithm) int {
				return cmp.Compare(a.String(), b.String())
			})
			require.Equal(t, tc.Expected, algs, `results should match`)
		})
	}
}

// TestAlgorithmsForKeyECDHRejects is a regression test for JWS-004:
// ecdh.{Public,Private}Key values are for key agreement (X25519/X448),
// not signing. AlgorithmsForKey must reject them instead of handing back
// the generic OKP algorithm list and deferring the type error to the
// signing stack.
func TestAlgorithmsForKeyECDHRejects(t *testing.T) {
	x25519priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err, `ecdh.X25519().GenerateKey should succeed`)
	x25519pub := x25519priv.PublicKey()

	testcases := []struct {
		Name string
		Key  any
	}{
		{Name: "*ecdh.PrivateKey", Key: x25519priv},
		{Name: "ecdh.PrivateKey (value)", Key: *x25519priv},
		{Name: "*ecdh.PublicKey", Key: x25519pub},
		{Name: "ecdh.PublicKey (value)", Key: *x25519pub},
		{Name: "empty *ecdh.PublicKey", Key: &ecdh.PublicKey{}},
	}

	for _, tc := range testcases {
		t.Run(tc.Name, func(t *testing.T) {
			_, err := jws.AlgorithmsForKey(tc.Key)
			require.Error(t, err, `AlgorithmsForKey should reject ecdh keys`)
		})
	}
}

// unclassifiableSigner is a crypto.Signer whose Public() is itself a
// crypto.Signer, so AlgorithmsForKey cannot classify it — the documented
// "opaque KMS-backed signer" escape hatch in validateAlgorithmForKey.
type unclassifiableSigner struct{}

func (unclassifiableSigner) Public() crypto.PublicKey { return unclassifiableSigner{} }
func (unclassifiableSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("unclassifiableSigner.Sign not implemented")
}

// TestValidateAlgorithmForKeyBoundary is a regression test for JWS-054:
// validateAlgorithmForKey must reject unrecognized key types at the option
// boundary, while still allowing the narrow opaque-crypto.Signer escape
// hatch so KMS-style signers reach the crypto layer.
func TestValidateAlgorithmForKeyBoundary(t *testing.T) {
	t.Run("unknown struct rejected at option boundary", func(t *testing.T) {
		type bogusKey struct{}
		_, err := jws.Sign([]byte("payload"), jws.WithKey(jwa.RS256(), bogusKey{}))
		require.Error(t, err, `jws.Sign must reject unknown key types`)
		require.Contains(t, err.Error(), "unknown key type",
			`error must come from AlgorithmsForKey, not the signing stack`)
	})
	t.Run("opaque crypto.Signer still accepted", func(t *testing.T) {
		// Not expected to actually sign — we only assert the boundary
		// check does not short-circuit before the signing stack.
		_, err := jws.Sign([]byte("payload"), jws.WithKey(jwa.RS256(), unclassifiableSigner{}))
		require.Error(t, err, `signing must ultimately fail`)
		require.NotContains(t, err.Error(), "unknown key type",
			`opaque crypto.Signer must bypass the option-boundary check`)
		require.NotContains(t, err.Error(), "is not compatible with key type",
			`opaque crypto.Signer must bypass the compatibility check`)
	})
	t.Run("rsa key with incompatible alg still rejected", func(t *testing.T) {
		privkey, err := jwxtest.GenerateRsaKey()
		require.NoError(t, err, `GenerateRsaKey should succeed`)
		_, err = jws.Sign([]byte("payload"), jws.WithKey(jwa.ES256(), privkey))
		require.Error(t, err, `jws.Sign must reject incompatible alg`)
		require.Contains(t, err.Error(), "is not compatible with key type")
	})
}

func TestGH681(t *testing.T) {
	privkey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err, "failed to create private key")

	buf, err := jws.Sign(nil, jws.WithKey(jwa.RS256(), privkey), jws.WithDetachedPayload([]byte("Lorem ipsum")))
	require.NoError(t, err, "failed to sign payload")

	t.Logf("%s", buf)

	_, err = jws.Verify(buf, jws.WithKey(jwa.RS256(), &privkey.PublicKey), jws.WithDetachedPayload([]byte("Lorem ipsum")))
	require.NoError(t, err, "failed to verify JWS message")
}

func TestGH840(t *testing.T) {
	// Go 1.19+ panics if elliptic curve operations are called against
	// a point that's _NOT_ on the curve. defaultParseKey calls Validate()
	// on the imported key so an untrusted JWK with an off-curve point is
	// rejected at the trust boundary — no bad key ever reaches jws.Sign
	// / jwt.Parse / jwk.PublicKeyOf.
	untrustedJWK := []byte(`{
		"kty": "EC",
		"crv": "P-256",
		"x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqx7D4",
		"y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
		"d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
	}`)

	_, err := jwk.ParseKey(untrustedJWK)
	require.Error(t, err, `jwk.ParseKey must reject an off-curve ECDSA JWK`)
}

func TestGH888(t *testing.T) {
	// This should fail because we're passing multiple keys (i.e. multiple signatures)
	// and yet we haven't specified JSON serialization
	_, err := jws.Sign([]byte(`foo`), jws.WithInsecureNoSignature(), jws.WithKey(jwa.HS256(), []byte(`bar`)))
	require.Error(t, err, `jws.Sign with multiple keys (including alg=none) should fail`)

	// This should pass because we can now have multiple signatures with JSON serialization
	signed, err := jws.Sign([]byte(`foo`), jws.WithInsecureNoSignature(), jws.WithKey(jwa.HS256(), []byte(`bar`)), jws.WithJSON())
	require.NoError(t, err, `jws.Sign should succeed`)

	message, err := jws.Parse(signed)
	require.NoError(t, err, `jws.Parse should succeed`)

	// Look for alg=none signature
	var foundNoSignature bool
	for _, sig := range message.Signatures() {
		if v, ok := sig.ProtectedHeaders().Algorithm(); !ok || v != jwa.NoSignature() {
			continue
		}

		require.Nil(t, sig.Signature(), `signature must be nil for alg=none`)
		foundNoSignature = true
	}
	require.True(t, foundNoSignature, `signature with no signature was found`)

	_, err = jws.Verify(signed)
	require.Error(t, err, `jws.Verify should fail`)

	_, err = jws.Verify(signed, jws.WithKey(jwa.NoSignature(), nil))
	require.Error(t, err, `jws.Verify should fail`)

	// Note: you can't do jws.Verify(..., jws.WithInsecureNoSignature())

	verified, err := jws.Verify(signed, jws.WithKey(jwa.HS256(), []byte(`bar`)))
	require.NoError(t, err, `jws.Verify should succeed`)
	require.Equal(t, []byte(`foo`), verified)
}

// Some stuff required for testing #910
// The original code used an external library to sign/verify, but here
// we just use a simple SHA256 digest here so that we don't force
// users to download an optional dependency
type s256SignerVerifier struct{}

var sha256Algo = jwa.NewSignatureAlgorithm("SillyTest256")

func (s256SignerVerifier) Sign(_ any, payload []byte) ([]byte, error) {
	h := sha256.Sum256(payload)
	return h[:], nil
}

func (s256SignerVerifier) Verify(_ any, payload, signature []byte) error {
	h := sha256.Sum256(payload)
	if !bytes.Equal(h[:], signature) {
		return fmt.Errorf("invalid signature: expected %q, got %q", base64.EncodeToString(h[:]), base64.EncodeToString(signature))
	}
	return nil
}

func TestGH910(t *testing.T) {
	// Note: This has global effect. You can't run this in parallel with other tests
	require.NoError(t, jws.RegisterSigner(sha256Algo, s256SignerVerifier{}))
	t.Cleanup(func() {
		jws.UnregisterSigner(sha256Algo)
	})

	require.NoError(t, jws.RegisterVerifier(sha256Algo, s256SignerVerifier{}))
	t.Cleanup(func() {
		jws.UnregisterVerifier(sha256Algo)
		jwa.UnregisterSignatureAlgorithm(sha256Algo)
	})

	// Now that we have established that the signature algorithm works,
	// we can proceed with the test
	const src = `Lorem Ipsum`
	signed, err := jws.Sign([]byte(src), jws.WithKey(sha256Algo, nil))
	require.NoError(t, err, `jws.Sign should succeed`)

	verified, err := jws.Verify(signed, jws.WithKey(sha256Algo, nil))
	require.NoError(t, err, `jws.Verify should succeed`)

	require.Equal(t, src, string(verified), `verified payload should match`)

	jws.UnregisterSigner(sha256Algo)

	// Now try after unregistering the signer for the algorithm
	_, err = jws.Sign([]byte(src), jws.WithKey(sha256Algo, nil))
	require.Error(t, err, `jws.Sign should succeed`)

	require.NoError(t, jws.RegisterSigner(sha256Algo, s256SignerVerifier{}))

	_, err = jws.Sign([]byte(src), jws.WithKey(sha256Algo, nil))
	require.NoError(t, err, `jws.Sign should succeed`)
}

func TestUnpaddedSignatureR(t *testing.T) {
	// I brute-forced generating a key and signature where the R portion
	// of the signature was not padded by using the following code in the
	// first run, then copied the result to the test
	/*
		for i := 0; i < 10000; i++ {
			rawKey, err := jwxtest.GenerateEcdsaKey(jwa.P256)
			require.NoError(t, err, `jwxtest.GenerateEcdsaJwk should succeed`)

			key, err := jwk.Import[jwk.Key](rawKey)
			require.NoError(t, err, `jwk.Import should succeed`)

			pubkey, _ := key.PublicKey()

			signed, err := jws.Sign([]byte("Lorem Ipsum"), jws.WithKey(jwa.ES256(), key))
			require.NoError(t, err, `jws.Sign should succeed`)

			message, err := jws.Parse(signed)
			require.NoError(t, err, `jws.Parse should succeed`)

			asJson, _ := json.Marshal(message)
			t.Logf("%s", asJson)

			for _, sig := range message.Signatures() {
				sigBytes := sig.Signature()
				if sigBytes[0] == 0x00 {
					// Found it!
					t.Logf("Found signature that can be unpadded.")
					t.Logf("Original signature: %q", base64.EncodeToString(sigBytes))

					//				unpaddedSig := append(sigBytes[1:31], sigBytes[32:]...)
					unpaddedSig := sigBytes[1:]
					t.Logf("Signature with first byte of R removed: %q", base64.EncodeToString(unpaddedSig))
					t.Logf("Original JWS payload: %q", signed)
					require.Len(t, unpaddedSig, 63)

					i := bytes.LastIndexByte(signed, tokens.Period)
					modified := append(signed[:i+1], base64.Encode(unpaddedSig)...)
					t.Logf("JWS payload with unpadded signature: %q", modified)

					// jws.Verify for sanity
					verified, err := jws.Verify(modified, jws.WithKey(jwa.ES256(), pubkey))
					require.NoError(t, err, `jws.Verify should succeed`)
					t.Logf("verified payload: %q", verified)

					buf, _ := json.Marshal(key)
					t.Logf("Private JWK: %s", buf)
					return
				}
			}
		}
	*/
	// Padded has R with a leading 0 (as it should)
	padded := "eyJhbGciOiJFUzI1NiJ9.TG9yZW0gSXBzdW0.ALFru4CRZDiAlVKyyHtlLGtXIAWxC3lXIlZuYO8G8a5ePzCwyw6c2FzWBZwrLaoLFZb_TcYs3TcZ8mhONPaavQ"
	// Unpadded has R with a leading 0 removed (31 bytes, WRONG)
	unpadded := "eyJhbGciOiJFUzI1NiJ9.TG9yZW0gSXBzdW0.sWu7gJFkOICVUrLIe2Usa1cgBbELeVciVm5g7wbxrl4_MLDLDpzYXNYFnCstqgsVlv9NxizdNxnyaE409pq9"

	// This is the private key used to sign the payload
	keySrc := `{"crv":"P-256","d":"MqGwMl-dlJFrMnu7rFyslPV8EdsVC7I4V19N-ADVqaU","kty":"EC","x":"Anf1p2lRrcXgZKpVRRC1xLxPiw_45PbOlygfbxvD8Es","y":"d0HiZq-aurVVLLtK-xqXPpzpWloZJNwKNve7akBDuvg"}`

	privKey, err := jwk.ParseKey([]byte(keySrc))
	require.NoError(t, err, `jwk.ParseKey should succeed`)

	pubKey, err := jwk.PublicKeyOf(privKey)
	require.NoError(t, err, `jwk.PublicKeyOf should succeed`)

	// Should always succeed
	payload, err := jws.Verify([]byte(padded), jws.WithKey(jwa.ES256(), pubKey))
	require.NoError(t, err, `jws.Verify should succeed`)
	require.Equal(t, "Lorem Ipsum", string(payload))

	// Should fail
	_, err = jws.Verify([]byte(unpadded), jws.WithKey(jwa.ES256(), pubKey))
	require.Error(t, err, `jws.Verify should fail`)
}

func TestValidateKey(t *testing.T) {
	privKey, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err, `jwxtest.GenerateRsaJwk should succeed`)

	signed, err := jws.Sign([]byte("Lorem Ipsum"), jws.WithKey(jwa.RS256(), privKey), jws.WithValidateKey(true))
	require.NoError(t, err, `jws.Sign should succeed`)

	// This should fail because D is empty
	require.NoError(t, privKey.Set(jwk.RSADKey, []byte(nil)), `jwk.Set should succeed`)
	_, err = jws.Sign([]byte("Lorem Ipsum"), jws.WithKey(jwa.RS256(), privKey), jws.WithValidateKey(true))
	require.Error(t, err, `jws.Sign should fail`)

	pubKey, err := jwk.PublicKeyOf(privKey)
	require.NoError(t, err, `jwk.PublicKeyOf should succeed`)

	n, ok := pubKey.(jwk.RSAPublicKey).N()
	require.True(t, ok, `N should be present`)

	// Set N to an empty value
	require.NoError(t, pubKey.Set(jwk.RSANKey, []byte(nil)), `jwk.Set should succeed`)

	// This is going to fail regardless, because the public key is now
	// invalid (empty N), but we want to make sure that it fails because
	// of the validation failing
	_, err = jws.Verify(signed, jws.WithKey(jwa.RS256(), pubKey), jws.WithValidateKey(true))
	require.Error(t, err, `jws.Verify should fail`)
	require.True(t, jwk.IsKeyValidationError(err), `jwk.IsKeyValidationError should return true`)

	// The following should now succeed, because N has been reinstated
	require.NoError(t, pubKey.Set(jwk.RSANKey, n), `jwk.Set should succeed`)
	_, err = jws.Verify(signed, jws.WithKey(jwa.RS256(), pubKey), jws.WithValidateKey(true))
	require.NoError(t, err, `jws.Verify should succeed`)
}

func TestEmptyProtectedField(t *testing.T) {
	// MEMO: this was the only test case from the original report
	// This passes. It should produce an invalid JWS message, but
	// that's not `jws.Parse`'s problem.
	_, err := jws.Parse([]byte(`{"signature": ""}`))
	require.NoError(t, err, `jws.Parse should fail`)

	// Also test that non-flattened serialization passes.
	_, err = jws.Parse([]byte(`{"signatures": [{}]}`))
	require.NoError(t, err, `jws.Parse should fail`)

	// MEMO: rest of the cases are present to be extra pedantic about it

	privKey, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err, `jwxtest.GenerateRsaJwk should succeed`)

	// This fails. `jws.Parse` works, but the subsequent verification
	// workflow fails to verify anything without the presence of a signature or
	// a protected header.
	_, err = jws.Verify([]byte(`{"signature": ""}`), jws.WithKey(jwa.RS256(), privKey))
	require.Error(t, err, `jws.Parse should fail`)

	// Create a valid signatre.
	signed, err := jws.Sign([]byte("Lorem Ipsum"), jws.WithKey(jwa.RS256(), privKey))
	require.NoError(t, err, `jws.Sign should succeed`)

	_, payload, signature, err := jwsbb.SplitCompact(signed)
	require.NoError(t, err, `jwsbb.SplitCompact should succeed`)

	// This fails as well. we have a valid signature and a valid
	// key to verify it, but no protected headers
	_, err = jws.Verify(
		fmt.Appendf(nil, `{"signature": "%s"}`, signature),
		jws.WithKey(jwa.RS256(), privKey),
	)
	require.Error(t, err, `jws.Verify should fail`)

	// Test for cases when we have an incomplete compact form JWS
	var buf bytes.Buffer
	buf.WriteRune(tokens.Period)
	buf.Write(payload)
	buf.WriteRune(tokens.Period)
	buf.Write(signature)
	invalidMessage := buf.Bytes()

	// This is an error because the format is simply wrong.
	// Whereas in the other JSON-based JWS's case the lack of protected field
	// is not a SYNTAX error, this one is, and therefore we barf.
	_, err = jws.Parse(invalidMessage)
	require.Error(t, err, `jws.Parse should fail`)
}

func TestParseFormat(t *testing.T) {
	privKey, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err, `jwxtest.GenerateRsaJwk should succeed`)

	signedCompact, err := jws.Sign([]byte("Lorem Ipsum"), jws.WithKey(jwa.RS256(), privKey), jws.WithValidateKey(true))
	require.NoError(t, err, `jws.Sign should succeed`)

	signedJSON, err := jws.Sign([]byte("Lorem Ipsum"), jws.WithKey(jwa.RS256(), privKey), jws.WithValidateKey(true), jws.WithJSON())
	require.NoError(t, err, `jws.Sign should succeed`)

	// Only compact formats should succeed
	_, err = jws.Verify(signedCompact, jws.WithKey(jwa.RS256(), privKey), jws.WithCompact())
	require.NoError(t, err, `jws.Verify should succeed`)
	_, err = jws.Verify(signedJSON, jws.WithKey(jwa.RS256(), privKey), jws.WithCompact())
	require.Error(t, err, `jws.Verify should fail`)
	_, err = jws.Parse(signedCompact, jws.WithCompact())
	require.NoError(t, err, `jws.Parse should succeed`)
	_, err = jws.Parse(signedJSON, jws.WithCompact())
	require.Error(t, err, `jws.Parse should fail`)

	// Only JSON formats should succeed
	_, err = jws.Verify(signedCompact, jws.WithKey(jwa.RS256(), privKey), jws.WithJSON())
	require.Error(t, err, `jws.Verify should fail`)
	_, err = jws.Verify(signedJSON, jws.WithKey(jwa.RS256(), privKey), jws.WithJSON())
	require.NoError(t, err, `jws.Verify should succeed`)
	_, err = jws.Parse(signedJSON, jws.WithJSON())
	require.NoError(t, err, `jws.Parse should succeed`)
	_, err = jws.Parse(signedCompact, jws.WithJSON())
	require.Error(t, err, `jws.Parse should fail`)

	// Either format should succeed
	_, err = jws.Verify(signedCompact, jws.WithKey(jwa.RS256(), privKey))
	require.NoError(t, err, `jws.Verify should succeed`)
	_, err = jws.Verify(signedCompact, jws.WithKey(jwa.RS256(), privKey), jws.WithJSON(), jws.WithCompact())
	require.NoError(t, err, `jws.Verify should succeed`)
	_, err = jws.Parse(signedCompact)
	require.NoError(t, err, `jws.Parse should succeed`)
	_, err = jws.Parse(signedCompact, jws.WithJSON(), jws.WithCompact())
	require.NoError(t, err, `jws.Parse should succeed`)

	_, err = jws.Verify(signedJSON, jws.WithKey(jwa.RS256(), privKey))
	require.NoError(t, err, `jws.Verify should succeed`)
	_, err = jws.Verify(signedJSON, jws.WithKey(jwa.RS256(), privKey), jws.WithJSON(), jws.WithCompact())
	require.NoError(t, err, `jws.Verify should succeed`)
	_, err = jws.Parse(signedJSON)
	require.NoError(t, err, `jws.Parse should succeed`)
	_, err = jws.Parse(signedJSON, jws.WithJSON(), jws.WithCompact())
	require.NoError(t, err, `jws.Parse should succeed`)
}

func BenchmarkSplitCompat(b *testing.B) {
	for b.Loop() {
		_, _, _, err := jwsbb.SplitCompact([]byte(exampleCompactSerialization))
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkSplitCompatString(b *testing.B) {
	for b.Loop() {
		_, _, _, err := jwsbb.SplitCompactString(exampleCompactSerialization)
		if err != nil {
			panic(err)
		}
	}
}

func TestMaxSignatures(t *testing.T) {
	key1, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err, `GenerateRsaKey should succeed`)
	key2, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err, `GenerateRsaKey should succeed`)

	// Build a valid JWS with JSON serialization (two signatures to get array format).
	signed, err := jws.Sign(
		[]byte("hello"),
		jws.WithJSON(),
		jws.WithKey(jwa.RS256(), key1),
		jws.WithKey(jwa.RS256(), key2),
	)
	require.NoError(t, err, `jws.Sign should succeed`)

	// Parse the JSON and extract a signature entry so we can duplicate it.
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(signed, &parsed))

	sigs, ok := parsed["signatures"].([]any)
	require.True(t, ok, `signatures field must be an array`)
	require.True(t, len(sigs) > 0)

	singleSig := sigs[0]

	makeMessage := func(n int) []byte {
		signatures := make([]any, n)
		for i := range signatures {
			signatures[i] = singleSig
		}
		msg := map[string]any{
			"payload":    parsed["payload"],
			"signatures": signatures,
		}
		buf, err := json.Marshal(msg)
		require.NoError(t, err)
		return buf
	}

	t.Run("parse rejects over global limit", func(t *testing.T) {
		msg := makeMessage(101)
		_, err := jws.Parse(msg)
		require.Error(t, err, `jws.Parse should fail with too many signatures`)
		require.Contains(t, err.Error(), `too many signatures`)
	})

	t.Run("parse accepts within global limit", func(t *testing.T) {
		msg := makeMessage(100)
		_, err := jws.Parse(msg)
		require.NoError(t, err, `jws.Parse should succeed within limit`)
	})

	t.Run("global settings override", func(t *testing.T) {
		jws.Settings(jws.WithMaxSignatures(5))
		defer jws.Settings(jws.WithMaxSignatures(100))

		msg := makeMessage(6)
		_, err := jws.Parse(msg)
		require.Error(t, err, `jws.Parse should fail with lowered limit`)
		require.Contains(t, err.Error(), `too many signatures`)

		msg = makeMessage(5)
		_, err = jws.Parse(msg)
		require.NoError(t, err, `jws.Parse should succeed at exactly the limit`)
	})

	t.Run("per-call parse override", func(t *testing.T) {
		jws.Settings(jws.WithMaxSignatures(5))
		defer jws.Settings(jws.WithMaxSignatures(100))

		msg := makeMessage(10)

		// Should fail with global limit
		_, err := jws.Parse(msg)
		require.Error(t, err, `jws.Parse should fail with global limit of 5`)

		// Should succeed with per-call override
		_, err = jws.Parse(msg, jws.WithMaxSignatures(10))
		require.NoError(t, err, `jws.Parse should succeed with per-call limit of 10`)
	})

	t.Run("rejects before decoding entries", func(t *testing.T) {
		// Build a payload with many tiny signature stubs. If the cap were
		// enforced only after Message.UnmarshalJSON finished decoding every
		// entry, this would allocate hundreds of thousands of Headers before
		// rejection (REV-JWS-20260414T114515Z-002).
		const n = 200000
		parts := make([]string, n)
		for i := range parts {
			parts[i] = `{"protected":"","signature":""}`
		}
		body := []byte(`{"payload":"","signatures":[` + strings.Join(parts, ",") + `]}`)

		_, err := jws.Parse(body, jws.WithMaxSignatures(16))
		require.Error(t, err, `jws.Parse should reject oversized signatures array`)
		require.Contains(t, err.Error(), `too many signatures`)
	})

	t.Run("verify inherits limit", func(t *testing.T) {
		jws.Settings(jws.WithMaxSignatures(5))
		defer jws.Settings(jws.WithMaxSignatures(100))

		msg := makeMessage(6)

		_, err := jws.Verify(msg, jws.WithKey(jwa.RS256(), &key1.PublicKey))
		require.Error(t, err, `jws.Verify should fail when signatures exceed limit`)
	})
}

func TestAlgorithmKeyMismatch(t *testing.T) {
	rsaKey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)

	ecKey, err := jwxtest.GenerateEcdsaKey(jwa.P256())
	require.NoError(t, err)

	edKey, err := jwxtest.GenerateEd25519Key()
	require.NoError(t, err)

	hmacKey := jwxtest.GenerateSymmetricKey()

	// Sign a valid HMAC message to use in Verify/VerifyCompactFast tests
	validCompact, err := jws.Sign([]byte("test"), jws.WithKey(jwa.HS256(), hmacKey))
	require.NoError(t, err)

	testcases := []struct {
		Name string
		Alg  jwa.SignatureAlgorithm
		Key  any
	}{
		{"RS256 with ECDSA key", jwa.RS256(), ecKey},
		{"RS256 with Ed25519 key", jwa.RS256(), edKey},
		{"RS256 with HMAC key", jwa.RS256(), hmacKey},
		{"ES256 with RSA key", jwa.ES256(), rsaKey},
		{"ES256 with Ed25519 key", jwa.ES256(), edKey},
		{"ES256 with HMAC key", jwa.ES256(), hmacKey},
		{"EdDSA with RSA key", jwa.EdDSA(), rsaKey},
		{"EdDSA with ECDSA key", jwa.EdDSA(), ecKey},
		{"EdDSA with HMAC key", jwa.EdDSA(), hmacKey},
		{"HS256 with RSA key", jwa.HS256(), rsaKey},
		{"HS256 with ECDSA key", jwa.HS256(), ecKey},
		{"HS256 with Ed25519 key", jwa.HS256(), edKey},
	}

	for _, tc := range testcases {
		t.Run("Sign/"+tc.Name, func(t *testing.T) {
			_, err := jws.Sign([]byte("payload"), jws.WithKey(tc.Alg, tc.Key))
			require.Error(t, err)
			require.True(t, errors.Is(err, jws.SignError()), `error should be SignError`)
			require.Contains(t, err.Error(), "not compatible")
		})
		t.Run("Verify/"+tc.Name, func(t *testing.T) {
			_, err := jws.Verify(validCompact, jws.WithKey(tc.Alg, tc.Key))
			require.Error(t, err)
			require.True(t, errors.Is(err, jws.VerifyError()), `error should be VerifyError`)
			require.Contains(t, err.Error(), "not compatible")
		})
		t.Run("VerifyCompactFast/"+tc.Name, func(t *testing.T) {
			_, err := jws.VerifyCompactFast(tc.Key, validCompact, tc.Alg)
			require.Error(t, err)
			require.True(t, errors.Is(err, jws.VerifyError()), `error should be VerifyError`)
			require.Contains(t, err.Error(), "not compatible")
		})
	}
}

// testCryptoSigner wraps a crypto.Signer so that AlgorithmsForKey
// doesn't match it as a concrete standard library type.
type testCryptoSigner struct {
	crypto.Signer
}

func TestAlgorithmsForKeyCryptoSigner(t *testing.T) {
	rsaKey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)

	signer := testCryptoSigner{rsaKey}

	t.Run("AlgorithmsForKey resolves via Public()", func(t *testing.T) {
		algs, err := jws.AlgorithmsForKey(signer)
		require.NoError(t, err, `AlgorithmsForKey should succeed for crypto.Signer wrapping RSA`)

		require.Contains(t, algs, jwa.RS256())
		require.Contains(t, algs, jwa.PS256())
	})

	t.Run("matching algorithm passes validation", func(t *testing.T) {
		signed, err := jws.Sign([]byte("payload"), jws.WithKey(jwa.RS256(), signer))
		require.NoError(t, err, `Sign with matching crypto.Signer should succeed`)

		_, err = jws.Verify(signed, jws.WithKey(jwa.RS256(), &rsaKey.PublicKey))
		require.NoError(t, err, `Verify should succeed`)
	})

	t.Run("mismatching algorithm is rejected early", func(t *testing.T) {
		_, err := jws.Sign([]byte("payload"), jws.WithKey(jwa.ES256(), signer))
		require.Error(t, err)
		require.True(t, errors.Is(err, jws.SignError()))
		require.Contains(t, err.Error(), "not compatible")
	})
}

func TestWithKeyRejectsNonSignatureAlgorithm(t *testing.T) {
	hmacKey := jwxtest.GenerateSymmetricKey()
	signed, err := jws.Sign([]byte("test"), jws.WithKey(jwa.HS256(), hmacKey))
	require.NoError(t, err)

	t.Run("Sign", func(t *testing.T) {
		// jwa.A128KW is a KeyEncryptionAlgorithm, not a SignatureAlgorithm.
		_, err := jws.Sign([]byte("test"), jws.WithKey(jwa.A128KW(), hmacKey))
		require.Error(t, err)
		require.True(t, errors.Is(err, jws.SignError()))
		require.Contains(t, err.Error(), "SignatureAlgorithm")
	})

	t.Run("Verify", func(t *testing.T) {
		// Previously the unchecked type assertion in verify_context would panic.
		_, err := jws.Verify(signed, jws.WithKey(jwa.A128KW(), hmacKey))
		require.Error(t, err)
		require.True(t, errors.Is(err, jws.VerifyError()))
		require.Contains(t, err.Error(), "SignatureAlgorithm")
	})
}

func TestCompactErrorsUseSignError(t *testing.T) {
	t.Run("invalid signature count", func(t *testing.T) {
		_, err := jws.Compact(jws.NewMessage())
		require.Error(t, err)
		require.True(t, errors.Is(err, jws.SignError()))
		require.Contains(t, err.Error(), "jws.Compact: cannot serialize message")
		require.NotContains(t, err.Error(), "jws.Compress")
	})

	t.Run("marshal headers failure", func(t *testing.T) {
		hdrs := jws.NewHeaders()
		require.NoError(t, hdrs.Set("broken", make(chan int)))

		msg := jws.NewMessage().
			SetPayload([]byte("payload")).
			AppendSignature(jws.NewSignature().
				SetProtectedHeaders(hdrs).
				SetSignature([]byte("sig")))

		_, err := jws.Compact(msg)
		require.Error(t, err)
		require.True(t, errors.Is(err, jws.SignError()))
		require.Contains(t, err.Error(), "jws.Compact: failed to marshal headers")
		require.NotContains(t, err.Error(), "jws.Compress")
	})

	t.Run("unencoded payload contains dot", func(t *testing.T) {
		hdrs := jws.NewHeaders()
		require.NoError(t, hdrs.Set("b64", false))

		msg := jws.NewMessage().
			SetPayload([]byte("a.b")).
			AppendSignature(jws.NewSignature().
				SetProtectedHeaders(hdrs).
				SetSignature([]byte("sig")))

		_, err := jws.Compact(msg)
		require.Error(t, err)
		require.True(t, errors.Is(err, jws.SignError()))
		require.Contains(t, err.Error(), `jws.Compact: payload must not contain a "."`)
		require.NotContains(t, err.Error(), "jws.Compress")
	})
}

func TestVerifyCompactFastHeaderAlgCrossCheck(t *testing.T) {
	hmacKey := jwxtest.GenerateSymmetricKey()

	t.Run("Match", func(t *testing.T) {
		signed, err := jws.Sign([]byte("payload"), jws.WithKey(jwa.HS256(), hmacKey))
		require.NoError(t, err)

		payload, err := jws.VerifyCompactFast(hmacKey, signed, jwa.HS256())
		require.NoError(t, err)
		require.Equal(t, []byte("payload"), payload)
	})

	t.Run("Mismatch/HS256 signed verified as HS384", func(t *testing.T) {
		// HS256 and HS384 both accept symmetric []byte keys, so
		// validateAlgorithmForKey passes and the new header cross-check
		// is the discipline that catches the divergence.
		signed, err := jws.Sign([]byte("payload"), jws.WithKey(jwa.HS256(), hmacKey))
		require.NoError(t, err)

		_, err = jws.VerifyCompactFast(hmacKey, signed, jwa.HS384())
		require.Error(t, err)
		require.True(t, errors.Is(err, jws.VerifyError()), `error should be VerifyError`)
		require.True(t, errors.Is(err, jws.VerificationError()), `error should be VerificationError`)
		require.Contains(t, err.Error(), `"alg"`)
		require.Contains(t, err.Error(), "HS256")
		require.Contains(t, err.Error(), "HS384")
	})

	t.Run("Missing alg in header", func(t *testing.T) {
		// Hand-assemble a compact JWS whose protected header omits "alg".
		hdr := base64.EncodeToString([]byte(`{"typ":"JWT"}`))
		payload := base64.EncodeToString([]byte("payload"))
		sig := base64.EncodeToString([]byte("not-a-real-signature"))
		compact := []byte(hdr + "." + payload + "." + sig)

		_, err := jws.VerifyCompactFast(hmacKey, compact, jwa.HS256())
		require.Error(t, err)
		require.True(t, errors.Is(err, jws.VerifyError()), `error should be VerifyError`)
		require.True(t, errors.Is(err, jws.VerificationError()), `error should be VerificationError`)
		require.Contains(t, err.Error(), `"alg"`)
	})
}

func TestSignKidConflict(t *testing.T) {
	t.Parallel()

	key, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.KeyIDKey, "key-kid"), `set kid on key`)

	hdr := jws.NewHeaders()
	require.NoError(t, hdr.Set(jws.KeyIDKey, "header-kid"))

	_, err = jws.Sign([]byte("payload"),
		jws.WithKey(jwa.RS256(), key, jws.WithProtectedHeaders(hdr)))
	require.Error(t, err, `Sign should fail on kid mismatch`)
	require.Contains(t, err.Error(), `header-kid`, `error should name both kids`)
	require.Contains(t, err.Error(), `key-kid`, `error should name both kids`)
	require.Contains(t, err.Error(), `conflicting "kid" values`)
}

func TestSignKidMatch(t *testing.T) {
	// Sign still succeeds when the caller-supplied kid agrees with the
	// key's kid — this is a legitimate pattern (e.g. echoing the kid
	// through a template Headers) and must stay working.
	t.Parallel()

	key, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.KeyIDKey, "same-kid"))

	hdr := jws.NewHeaders()
	require.NoError(t, hdr.Set(jws.KeyIDKey, "same-kid"))

	_, err = jws.Sign([]byte("payload"),
		jws.WithKey(jwa.RS256(), key, jws.WithProtectedHeaders(hdr)))
	require.NoError(t, err, `matching kids should sign cleanly`)
}
