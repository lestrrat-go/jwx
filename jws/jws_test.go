package jws_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/httprc"
	"github.com/lestrrat-go/jwx/v2/internal/base64"
	"github.com/lestrrat-go/jwx/v2/internal/json"
	"github.com/lestrrat-go/jwx/v2/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/lestrrat-go/jwx/v2/x25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const examplePayload = `{"iss":"joe",` + "\r\n" + ` "exp":1300819380,` + "\r\n" + ` "http://example.com/is_root":true}`
const exampleCompactSerialization = `eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`
const badValue = "%badvalue%"

var hasES256K bool

func TestSanity(t *testing.T) {
	t.Run("sanity: Verify with single key", func(t *testing.T) {
		key, err := jwk.ParseKey([]byte(`{
    "kty": "oct",
    "k": "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
  }`))
		require.NoError(t, err, `jwk.ParseKey should succeed`)
		payload, err := jws.Verify([]byte(exampleCompactSerialization), jws.WithKey(jwa.HS256, key))
		require.NoError(t, err, `jws.Verify should succeed`)
		require.Equal(t, []byte(examplePayload), payload, `payloads should match`)
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

func testRoundtrip(t *testing.T, payload []byte, alg jwa.SignatureAlgorithm, signKey interface{}, keys map[string]interface{}) {
	jwkKey, err := jwk.FromRaw(signKey)
	require.NoError(t, err, `jwk.New should succeed`)
	signKeys := []struct {
		Name string
		Key  interface{}
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

	if es, ok := signKey.(*ecdsa.PrivateKey); ok {
		signKeys = append(signKeys, struct {
			Name string
			Key  interface{}
		}{
			Name: "crypto.Hash",
			Key:  &dummyECDSACryptoSigner{raw: es},
		})
	} else if cs, ok := signKey.(crypto.Signer); ok {
		signKeys = append(signKeys, struct {
			Name string
			Key  interface{}
		}{
			Name: "crypto.Hash",
			Key:  &dummyCryptoSigner{raw: cs},
		})
	}

	for _, key := range signKeys {
		key := key
		t.Run(key.Name, func(t *testing.T) {
			signed, err := jws.Sign(payload, jws.WithKey(alg, key.Key))
			require.NoError(t, err, "jws.Sign should succeed")

			parsers := map[string]func([]byte) (*jws.Message, error){
				"ParseReader(io.Reader)": func(b []byte) (*jws.Message, error) { return jws.ParseReader(bufio.NewReader(bytes.NewReader(b))) },
				"Parse([]byte)":          func(b []byte) (*jws.Message, error) { return jws.Parse(b) },
				"ParseString(string)":    func(b []byte) (*jws.Message, error) { return jws.ParseString(string(b)) },
			}
			for name, f := range parsers {
				name := name
				f := f
				t.Run(name, func(t *testing.T) {
					t.Parallel()
					m, err := f(signed)
					require.NoError(t, err, "(%s) %s is successful", alg, name)
					require.Equal(t, payload, m.Payload(), "(%s) %s: Payload is decoded", alg, name)
				})
			}

			for name, testKey := range keys {
				name := name
				testKey := testKey
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
		jwkKey, _ := jwk.FromRaw(sharedkey)
		keys := map[string]interface{}{
			"[]byte":  sharedkey,
			"jwk.Key": jwkKey,
		}
		hmacAlgorithms := []jwa.SignatureAlgorithm{jwa.HS256, jwa.HS384, jwa.HS512}
		for _, alg := range hmacAlgorithms {
			alg := alg
			t.Run(alg.String(), func(t *testing.T) {
				t.Parallel()
				testRoundtrip(t, payload, alg, sharedkey, keys)
			})
		}
	})
	t.Run("ECDSA", func(t *testing.T) {
		t.Parallel()
		key, err := jwxtest.GenerateEcdsaKey(jwa.P521)
		require.NoError(t, err, "ECDSA key generated")
		jwkKey, _ := jwk.FromRaw(key.PublicKey)
		keys := map[string]interface{}{
			"Verify(ecdsa.PublicKey)":  key.PublicKey,
			"Verify(*ecdsa.PublicKey)": &key.PublicKey,
			"Verify(jwk.Key)":          jwkKey,
		}
		for _, alg := range []jwa.SignatureAlgorithm{jwa.ES256, jwa.ES384, jwa.ES512} {
			alg := alg
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
		jwkKey, _ := jwk.FromRaw(key.PublicKey)
		keys := map[string]interface{}{
			"Verify(rsa.PublicKey)":  key.PublicKey,
			"Verify(*rsa.PublicKey)": &key.PublicKey,
			"Verify(jwk.Key)":        jwkKey,
		}
		for _, alg := range []jwa.SignatureAlgorithm{jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512} {
			alg := alg
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
		jwkKey, _ := jwk.FromRaw(pubkey)
		keys := map[string]interface{}{
			"Verify(ed25519.Public())": pubkey,
			// Meh, this doesn't work
			// "Verify(*ed25519.Public())": &pubkey,
			"Verify(jwk.Key)": jwkKey,
		}
		for _, alg := range []jwa.SignatureAlgorithm{jwa.EdDSA} {
			alg := alg
			t.Run(alg.String(), func(t *testing.T) {
				t.Parallel()
				testRoundtrip(t, payload, alg, key, keys)
			})
		}
	})
}

func TestSignMulti2(t *testing.T) {
	sharedkey := []byte("Avracadabra")
	payload := []byte("Lorem ipsum")
	hmacAlgorithms := []jwa.SignatureAlgorithm{jwa.HS256, jwa.HS384, jwa.HS512}
	var signed []byte
	t.Run("Sign", func(t *testing.T) {
		var options = []jws.SignOption{jws.WithJSON()}
		for _, alg := range hmacAlgorithms {
			options = append(options, jws.WithKey(alg, sharedkey)) // (signer, sharedkey, nil, nil))
		}
		var err error
		signed, err = jws.Sign(payload, options...)
		require.NoError(t, err, `jws.SignMulti should succeed`)
	})
	for _, alg := range hmacAlgorithms {
		alg := alg
		t.Run("Verify "+alg.String(), func(t *testing.T) {
			m := jws.NewMessage()
			verified, err := jws.Verify(signed, jws.WithKey(alg, sharedkey), jws.WithMessage(m))
			require.NoError(t, err, "Verify succeeded")
			require.Equal(t, payload, verified, "verified payload matches")

			// XXX This actally doesn't really test much, but if there was anything
			// wrong, the process should have failed well before reaching here
			require.Equal(t, payload, m.Payload(), "message payload matches")
		})
	}
}

func TestEncode(t *testing.T) {
	t.Parallel()

	// HS256Compact tests that https://tools.ietf.org/html/rfc7515#appendix-A.1 works
	t.Run("HS256Compact", func(t *testing.T) {
		t.Parallel()
		const hdr = `{"typ":"JWT",` + "\r\n" + ` "alg":"HS256"}`
		const hmacKey = `AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow`
		const expected = `eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`

		hmacKeyDecoded, err := base64.DecodeString(hmacKey)
		require.NoError(t, err, "HMAC base64 decoded successful")

		hdrbuf := base64.Encode([]byte(hdr))
		payload := base64.Encode([]byte(examplePayload))

		signingInput := bytes.Join(
			[][]byte{
				hdrbuf,
				payload,
			},
			[]byte{'.'},
		)

		sign, err := jws.NewSigner(jwa.HS256)
		require.NoError(t, err, "HMAC signer created successfully")

		signature, err := sign.Sign(signingInput, hmacKeyDecoded)
		require.NoError(t, err, "PayloadSign is successful")
		sigbuf := base64.Encode(signature)

		encoded := bytes.Join(
			[][]byte{
				signingInput,
				sigbuf,
			},
			[]byte{'.'},
		)
		require.Equal(t, expected, string(encoded), "generated compact serialization should match")

		msg, err := jws.ParseReader(bytes.NewReader(encoded))
		require.NoError(t, err, "Parsing compact encoded serialization succeeds")

		signatures := msg.Signatures()
		require.Len(t, signatures, 1, `there should be exactly one signature`)

		algorithm := signatures[0].ProtectedHeaders().Algorithm()
		if algorithm != jwa.HS256 {
			t.Fatal("Algorithm in header does not match")
		}

		v, err := jws.NewVerifier(jwa.HS256)
		require.NoError(t, err, "HmacVerify created")

		require.NoError(t, v.Verify(signingInput, signature, hmacKeyDecoded), "Verify succeeds")
	})
	t.Run("ES512Compact", func(t *testing.T) {
		t.Parallel()
		// ES256Compact tests that https://tools.ietf.org/html/rfc7515#appendix-A.3 works
		hdr := []byte{123, 34, 97, 108, 103, 34, 58, 34, 69, 83, 53, 49, 50, 34, 125}
		const jwksrc = `{
"kty":"EC",
"crv":"P-521",
"x":"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk",
"y":"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2",
"d":"AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C"
}`

		// "Payload"
		jwsPayload := []byte{80, 97, 121, 108, 111, 97, 100}

		standardHeaders := jws.NewHeaders()
		require.NoError(t, json.Unmarshal(hdr, standardHeaders), `parsing headers should succeed`)

		alg := standardHeaders.Algorithm()

		jwkKey, err := jwk.ParseKey([]byte(jwksrc))
		if err != nil {
			t.Fatal("Failed to parse JWK")
		}
		var key interface{}
		require.NoError(t, jwkKey.Raw(&key), `jwk.Raw should succeed`)
		var jwsCompact []byte
		jwsCompact, err = jws.Sign(jwsPayload, jws.WithKey(alg, key))
		if err != nil {
			t.Fatal("Failed to sign message")
		}

		// Verify with standard ecdsa library
		_, _, jwsSignature, err := jws.SplitCompact(jwsCompact)
		if err != nil {
			t.Fatal("Failed to split compact JWT")
		}

		decodedJwsSignature, err := base64.Decode(jwsSignature)
		require.NoError(t, err, `base64.Decode should succeed`)
		r, s := &big.Int{}, &big.Int{}
		n := len(decodedJwsSignature) / 2
		r.SetBytes(decodedJwsSignature[:n])
		s.SetBytes(decodedJwsSignature[n:])
		signingHdr := base64.Encode(hdr)
		signingPayload := base64.Encode(jwsPayload)

		jwsSigningInput := bytes.Join(
			[][]byte{
				signingHdr,
				signingPayload,
			},
			[]byte{'.'},
		)
		hashed512 := sha512.Sum512(jwsSigningInput)
		ecdsaPrivateKey := key.(*ecdsa.PrivateKey)
		require.True(t, ecdsa.Verify(&ecdsaPrivateKey.PublicKey, hashed512[:], r, s), "ecdsa.Verify should succeed")

		// Verify with API library
		publicKey, err := jwk.PublicRawKeyOf(key)
		require.NoError(t, err, `jwk.PublicRawKeyOf should succeed`)
		verifiedPayload, err := jws.Verify(jwsCompact, jws.WithKey(alg, publicKey))
		if err != nil || string(verifiedPayload) != string(jwsPayload) {
			t.Fatal("Failed to verify message")
		}
	})
	t.Run("RS256Compact", func(t *testing.T) {
		t.Parallel()
		// RS256Compact tests that https://tools.ietf.org/html/rfc7515#appendix-A.2 works
		const hdr = `{"alg":"RS256"}`
		const expected = `eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw`
		const jwksrc = `{
    "kty":"RSA",
    "n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
    "e":"AQAB",
    "d":"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
    "p":"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc",
    "q":"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",
    "dp":"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",
    "dq":"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",
    "qi":"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"
  }`

		privkey, err := jwk.ParseKey([]byte(jwksrc))
		require.NoError(t, err, `parsing jwk should be successful`)

		var rawkey rsa.PrivateKey
		require.NoError(t, privkey.Raw(&rawkey), `obtaining raw key should succeed`)

		sign, err := jws.NewSigner(jwa.RS256)
		require.NoError(t, err, "RsaSign created successfully")

		hdrbuf := base64.Encode([]byte(hdr))
		payload := base64.Encode([]byte(examplePayload))
		signingInput := bytes.Join(
			[][]byte{
				hdrbuf,
				payload,
			},
			[]byte{'.'},
		)
		signature, err := sign.Sign(signingInput, rawkey)
		require.NoError(t, err, "PayloadSign is successful")
		sigbuf := base64.Encode(signature)

		encoded := bytes.Join(
			[][]byte{
				signingInput,
				sigbuf,
			},
			[]byte{'.'},
		)

		require.Equal(t, expected, string(encoded), "generated compact serialization should match")

		msg, err := jws.ParseReader(bytes.NewReader(encoded))
		require.NoError(t, err, "Parsing compact encoded serialization succeeds")

		signatures := msg.Signatures()
		require.Len(t, signatures, 1, `there should be exactly one signature`)

		algorithm := signatures[0].ProtectedHeaders().Algorithm()
		if algorithm != jwa.RS256 {
			t.Fatal("Algorithm in header does not match")
		}

		v, err := jws.NewVerifier(jwa.RS256)
		require.NoError(t, err, "Verify created")
		require.NoError(t, v.Verify(signingInput, signature, rawkey.PublicKey), "Verify succeeds")
	})
	t.Run("ES256Compact", func(t *testing.T) {
		t.Parallel()
		// ES256Compact tests that https://tools.ietf.org/html/rfc7515#appendix-A.3 works
		const hdr = `{"alg":"ES256"}`
		const jwksrc = `{
    "kty":"EC",
    "crv":"P-256",
    "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    "d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
  }`
		privkey, err := jwk.ParseKey([]byte(jwksrc))
		require.NoError(t, err, `parsing jwk should succeed`)

		var rawkey ecdsa.PrivateKey
		require.NoError(t, privkey.Raw(&rawkey), `obtaining raw key should succeed`)

		signer, err := jws.NewSigner(jwa.ES256)
		require.NoError(t, err, "RsaSign created successfully")

		hdrbuf := base64.Encode([]byte(hdr))
		payload := base64.Encode([]byte(examplePayload))
		signingInput := bytes.Join(
			[][]byte{
				hdrbuf,
				payload,
			},
			[]byte{'.'},
		)
		signature, err := signer.Sign(signingInput, &rawkey)
		require.NoError(t, err, "PayloadSign is successful")
		sigbuf := base64.Encode(signature)
		require.NoError(t, err, "base64 encode successful")

		encoded := bytes.Join(
			[][]byte{
				signingInput,
				sigbuf,
			},
			[]byte{'.'},
		)

		// The signature contains random factor, so unfortunately we can't match
		// the output against a fixed expected outcome. We'll wave doing an
		// exact match, and just try to verify using the signature

		msg, err := jws.ParseReader(bytes.NewReader(encoded))
		require.NoError(t, err, "Parsing compact encoded serialization succeeds")

		signatures := msg.Signatures()
		require.Len(t, signatures, 1, `there should be exactly one signature`)

		algorithm := signatures[0].ProtectedHeaders().Algorithm()
		if algorithm != jwa.ES256 {
			t.Fatal("Algorithm in header does not match")
		}

		v, err := jws.NewVerifier(jwa.ES256)
		require.NoError(t, err, "EcdsaVerify created")
		require.NoError(t, v.Verify(signingInput, signature, rawkey.PublicKey), "Verify succeeds")
	})
	t.Run("EdDSACompact", func(t *testing.T) {
		t.Parallel()
		// EdDSACompact tests that https://tools.ietf.org/html/rfc8037#appendix-A.1-5 works
		const hdr = `{"alg":"EdDSA"}`
		const jwksrc = `{
    "kty":"OKP",
    "crv":"Ed25519",
    "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
    "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
  }`
		const examplePayload = `Example of Ed25519 signing`
		const expected = `hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg`
		expectedDecoded, err := base64.Decode([]byte(expected))
		require.NoError(t, err, "Expected Signature decode successful")

		privkey, err := jwk.ParseKey([]byte(jwksrc))
		require.NoError(t, err, `parsing jwk should succeed`)

		var rawkey ed25519.PrivateKey
		require.NoError(t, privkey.Raw(&rawkey), `obtaining raw key should succeed`)

		signer, err := jws.NewSigner(jwa.EdDSA)
		require.NoError(t, err, "EdDSASign created successfully")

		hdrbuf := base64.Encode([]byte(hdr))
		payload := base64.Encode([]byte(examplePayload))
		signingInput := bytes.Join(
			[][]byte{
				hdrbuf,
				payload,
			},
			[]byte{'.'},
		)

		signature, err := signer.Sign(signingInput, rawkey)
		require.NoError(t, err, "PayloadSign is successful")
		sigbuf := base64.Encode(signature)
		encoded := bytes.Join(
			[][]byte{
				signingInput,
				sigbuf,
			},
			[]byte{'.'},
		)

		// The signature contains random factor, so unfortunately we can't match
		// the output against a fixed expected outcome. We'll wave doing an
		// exact match, and just try to verify using the signature

		msg, err := jws.ParseReader(bytes.NewReader(encoded))
		require.NoError(t, err, "Parsing compact encoded serialization succeeds")

		signatures := msg.Signatures()
		require.Len(t, signatures, 1, `there should be exactly one signature`)

		algorithm := signatures[0].ProtectedHeaders().Algorithm()
		if algorithm != jwa.EdDSA {
			t.Fatal("Algorithm in header does not match")
		}

		v, err := jws.NewVerifier(jwa.EdDSA)
		require.NoError(t, err, "EcdsaVerify created")
		require.NoError(t, v.Verify(signingInput, signature, rawkey.Public()), "Verify succeeds")
		require.Equal(t, signature, expectedDecoded, "signatures match")
	})
	t.Run("UnsecuredCompact", func(t *testing.T) {
		t.Parallel()
		s := `eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.`

		m, err := jws.ParseReader(strings.NewReader(s))
		require.NoError(t, err, "Parsing compact serialization")

		{
			v := map[string]interface{}{}
			require.NoError(t, json.Unmarshal(m.Payload(), &v), "Unmarshal payload")
			require.Equal(t, v["iss"], "joe", "iss matches")
			require.Equal(t, int(v["exp"].(float64)), 1300819380, "exp matches")
			require.Equal(t, v["http://example.com/is_root"], true, "'http://example.com/is_root' matches")
		}

		require.Len(t, m.Signatures(), 1, "There should be 1 signature")

		signatures := m.Signatures()
		algorithm := signatures[0].ProtectedHeaders().Algorithm()
		if algorithm != jwa.NoSignature {
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
				var payload []byte
				for i := 0; i < size; i++ {
					payload = append(payload, 'X')
				}
				payload = append(payload, '.')
				for i := 0; i < size; i++ {
					payload = append(payload, 'Y')
				}
				payload = append(payload, '.')

				for i := 0; i < size; i++ {
					payload = append(payload, 'Y')
				}

				// Test using bytes, reader optimized and non-optimized path
				for _, method := range []int{0, 1, 2} {
					var x, y, z []byte
					var err error
					switch method {
					case 0: // bytes
						x, y, z, err = jws.SplitCompact(payload)
					case 1: // un-optimized io.Reader
						x, y, z, err = jws.SplitCompactReader(bytes.NewReader(payload))
					default: // optimized io.Reader
						x, y, z, err = jws.SplitCompactReader(bufio.NewReader(bytes.NewReader(payload)))
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

func TestPublicHeaders(t *testing.T) {
	key, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err, "GenerateKey should succeed")

	signer, err := jws.NewSigner(jwa.RS256)
	require.NoError(t, err, "jws.NewSigner should succeed")
	_ = signer // TODO

	pubkey := key.PublicKey
	pubjwk, err := jwk.FromRaw(&pubkey)
	require.NoError(t, err, "NewRsaPublicKey should succeed")
	_ = pubjwk // TODO
}

func TestDecode_ES384Compact_NoSigTrim(t *testing.T) {
	incoming := "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6IjE5MzFmZTQ0YmFhMWNhZTkyZWUzNzYzOTQ0MDU1OGMwODdlMTRlNjk5ZWU5NjVhM2Q1OGU1MmU2NGY4MDE0NWIifQ.eyJpc3MiOiJicmt0LWNsaS0xLjAuN3ByZTEiLCJpYXQiOjE0ODQ2OTU1MjAsImp0aSI6IjgxYjczY2Y3In0.DdFi0KmPHSv4PfIMGcWGMSRLmZsfRPQ3muLFW6Ly2HpiLFFQWZ0VEanyrFV263wjlp3udfedgw_vrBLz3XC8CkbvCo_xeHMzaTr_yfhjoheSj8gWRLwB-22rOnUX_M0A"
	t.Logf("incoming = '%s'", incoming)
	const jwksrc = `{
    "kty":"EC",
    "crv":"P-384",
    "x":"YHVZ4gc1RDoqxKm4NzaN_Y1r7R7h3RM3JMteC478apSKUiLVb4UNytqWaLoE6ygH",
    "y":"CRKSqP-aYTIsqJfg_wZEEYUayUR5JhZaS2m4NLk2t1DfXZgfApAJ2lBO0vWKnUMp"
  }`

	pubkey, err := jwk.ParseKey([]byte(jwksrc))
	require.NoError(t, err, `parsing jwk should be successful`)

	var rawkey ecdsa.PublicKey
	require.NoError(t, pubkey.Raw(&rawkey), `obtaining raw key should succeed`)

	v, err := jws.NewVerifier(jwa.ES384)
	require.NoError(t, err, "EcdsaVerify created")

	protected, payload, signature, err := jws.SplitCompact([]byte(incoming))
	require.NoError(t, err, `jws.SplitCompact should succeed`)

	var buf bytes.Buffer
	buf.Write(protected)
	buf.WriteByte('.')
	buf.Write(payload)

	decodedSignature, err := base64.Decode(signature)
	require.NoError(t, err, `decoding signature should succeed`)
	require.NoError(t, v.Verify(buf.Bytes(), decodedSignature, rawkey), "Verify succeeds")
}

func TestReadFile(t *testing.T) {
	t.Parallel()

	f, err := os.CreateTemp("", "test-read-file-*.jws")
	require.NoError(t, err, `io.CreateTemp should succeed`)
	defer f.Close()

	fmt.Fprintf(f, "%s", exampleCompactSerialization)

	if _, err := jws.ReadFile(f.Name()); !assert.NoError(t, err, `jws.ReadFile should succeed`) {
		return
	}
}

func TestVerifyNonUniqueKid(t *testing.T) {
	const payload = "Lorem ipsum"
	const kid = "notUniqueKid"
	privateKey, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err, "jwxtest.GenerateJwk should succeed")
	_ = privateKey.Set(jwk.KeyIDKey, kid)
	signed, err := jws.Sign([]byte(payload), jws.WithKey(jwa.RS256, privateKey))
	require.NoError(t, err, `jws.Sign should succeed`)
	correctKey, _ := jwk.PublicKeyOf(privateKey)
	_ = correctKey.Set(jwk.AlgorithmKey, jwa.RS256)

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
				_ = wrongKey.Set(jwk.AlgorithmKey, jwa.RS256)
				return wrongKey
			},
		},
		{
			Name: `match 2 keys via same "kid", same key value but different alg`,
			Key: func() jwk.Key {
				wrongKey, _ := correctKey.Clone()
				_ = wrongKey.Set(jwk.KeyIDKey, kid)
				_ = wrongKey.Set(jwk.AlgorithmKey, jwa.RS512)
				return wrongKey
			},
		},
		{
			Name: `match 2 keys via same "kid", same key type but different alg`,
			Key: func() jwk.Key {
				privateKey, _ := jwxtest.GenerateRsaJwk()
				wrongKey, _ := jwk.PublicKeyOf(privateKey)
				_ = wrongKey.Set(jwk.KeyIDKey, kid)
				_ = wrongKey.Set(jwk.AlgorithmKey, jwa.RS512)
				return wrongKey
			},
		},
		{
			Name: `match 2 keys via same "kid" and different key type / alg`,
			Key: func() jwk.Key {
				privateKey, _ := jwxtest.GenerateEcdsaKey(jwa.P256)
				wrongKey, err := jwk.PublicKeyOf(privateKey)
				require.NoError(t, err, `jwk.PublicKeyOf should succeed`)
				_ = wrongKey.Set(jwk.KeyIDKey, kid)
				_ = wrongKey.Set(jwk.AlgorithmKey, jwa.ES256K)
				return wrongKey
			},
		},
	}

	for _, tc := range testcases {
		tc := tc
		wrongKey, err := tc.Key().Clone()
		require.NoError(t, err, `cloning wrong key should succeed`)
		for _, set := range []jwk.Set{makeSet(wrongKey, correctKey), makeSet(correctKey, wrongKey)} {
			set := set
			t.Run(tc.Name, func(t *testing.T) {
				// Try matching in different orders
				var usedKey jwk.Key
				_, err = jws.Verify(signed, jws.WithKeySet(set, jws.WithMultipleKeysPerKeyID(true)), jws.WithKeyUsed(&usedKey))
				require.NoError(t, err, `jws.Verify should succeed`)
				require.Equal(t, usedKey, correctKey)
			})
		}
	}
}

func TestVerifySet(t *testing.T) {
	t.Parallel()
	const payload = "Lorem ipsum"

	makeSet := func(privkey jwk.Key) jwk.Set {
		set := jwk.NewSet()
		k1, _ := jwk.FromRaw([]byte("abracadabra"))
		set.AddKey(k1)
		k2, _ := jwk.FromRaw([]byte("opensesame"))
		set.AddKey(k2)
		pubkey, _ := jwk.PublicKeyOf(privkey)
		pubkey.Set(jwk.AlgorithmKey, jwa.RS256)
		set.AddKey(pubkey)
		return set
	}

	for _, useJSON := range []bool{true, false} {
		useJSON := useJSON
		t.Run(fmt.Sprintf("useJSON=%t", useJSON), func(t *testing.T) {
			t.Parallel()
			t.Run(`match via "alg"`, func(t *testing.T) {
				t.Parallel()
				key, err := jwxtest.GenerateRsaJwk()
				require.NoError(t, err, "jwxtest.GenerateJwk should succeed")

				set := makeSet(key)
				signed, err := jws.Sign([]byte(payload), jws.WithKey(jwa.RS256, key))
				require.NoError(t, err, `jws.Sign should succeed`)
				if useJSON {
					m, err := jws.Parse(signed)
					require.NoError(t, err, `jws.Parse should succeed`)
					signed, err = json.Marshal(m)
					require.NoError(t, err, `json.Marshal should succeed`)
				}

				var used jwk.Key
				verified, err := jws.Verify(signed, jws.WithKeySet(set, jws.WithRequireKid(false)), jws.WithKeyUsed(&used))
				require.NoError(t, err, `jws.Verify should succeed`)
				require.Equal(t, []byte(payload), verified, `payload should match`)
				expected, _ := jwk.PublicKeyOf(key)
				thumb1, _ := expected.Thumbprint(crypto.SHA1)
				thumb2, _ := used.Thumbprint(crypto.SHA1)
				require.Equal(t, thumb1, thumb2, `keys should match`)
			})
			t.Run(`match via "kid"`, func(t *testing.T) {
				t.Parallel()

				key, err := jwxtest.GenerateRsaJwk()
				require.NoError(t, err, "jwxtest.GenerateJwk should succeed")
				key.Set(jwk.KeyIDKey, `mykey`)

				set := makeSet(key)
				signed, err := jws.Sign([]byte(payload), jws.WithKey(jwa.RS256, key))
				require.NoError(t, err, `jws.Sign should succeed`)
				if useJSON {
					m, err := jws.Parse(signed)
					require.NoError(t, err, `jws.Parse should succeed`)
					signed, err = json.Marshal(m)
					require.NoError(t, err, `json.Marshal should succeed`)
				}

				var used jwk.Key
				verified, err := jws.Verify(signed, jws.WithKeySet(set), jws.WithKeyUsed(&used))
				require.NoError(t, err, `jws.Verify should succeed`)
				require.Equal(t, []byte(payload), verified, `payload should match`)
				expected, _ := jwk.PublicKeyOf(key)
				thumb1, _ := expected.Thumbprint(crypto.SHA1)
				thumb2, _ := used.Thumbprint(crypto.SHA1)
				require.Equal(t, thumb1, thumb2, `keys should match`)
			})
		})
	}
}

func TestCustomField(t *testing.T) {
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

	signed, err := jws.Sign([]byte(payload), jws.WithKey(jwa.RS256, privkey, jws.WithProtectedHeaders(hdrs)))
	require.NoError(t, err, `jws.Sign should succeed`)

	t.Run("jws.Parse + json.Unmarshal", func(t *testing.T) {
		msg, err := jws.Parse(signed)
		require.NoError(t, err, `jws.Parse should succeed`)

		v, ok := msg.Signatures()[0].ProtectedHeaders().Get(`x-birthday`)
		require.True(t, ok, `msg.Signatures()[0].ProtectedHeaders().Get("x-birthday") should succeed`)
		require.Equal(t, expected, v, `values should match`)

		// Create JSON from jws.Message
		buf, err := json.Marshal(msg)
		require.NoError(t, err, `json.Marshal should succeed`)

		var msg2 jws.Message
		require.NoError(t, json.Unmarshal(buf, &msg2), `json.Unmarshal should succeed`)

		v, ok = msg2.Signatures()[0].ProtectedHeaders().Get(`x-birthday`)
		require.True(t, ok, `msg2.Signatures()[0].ProtectedHeaders().Get("x-birthday") should succeed`)
		require.Equal(t, expected, v, `values should match`)
	})
}

func TestWithMessage(t *testing.T) {
	key, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err, "jwxtest.Generate should succeed")

	const text = "hello, world"
	signed, err := jws.Sign([]byte(text), jws.WithKey(jwa.RS256, key))
	require.NoError(t, err, `jws.Sign should succeed`)

	m := jws.NewMessage()
	payload, err := jws.Verify(signed, jws.WithKey(jwa.RS256, key.PublicKey), jws.WithMessage(m))
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

		_, err := jws.Sign([]byte(payload), jws.WithKey(jwa.HS256, key, jws.WithProtectedHeaders(hdrs)))
		require.Error(t, err, `jws.Sign should fail`)
	})
	t.Run("Invalid usage when b64 = false and NOT detached", func(t *testing.T) {
		const payload = `$.02`
		hdrs := jws.NewHeaders()
		hdrs.Set("b64", false)
		hdrs.Set("crit", "b64")

		_, err := jws.Sign([]byte(payload), jws.WithKey(jwa.HS256, key, jws.WithProtectedHeaders(hdrs)), jws.WithDetachedPayload([]byte(payload)))
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
			tc := tc
			t.Run(tc.Name, func(t *testing.T) {
				hdrs := jws.NewHeaders()
				hdrs.Set("b64", false)
				hdrs.Set("crit", "b64")

				payload := tc.Payload
				signOptions := []jws.SignOption{jws.WithKey(jwa.HS256, key, jws.WithProtectedHeaders(hdrs))}
				var verifyOptions []jws.VerifyOption
				verifyOptions = append(verifyOptions, jws.WithKey(jwa.HS256, key))
				if tc.Detached {
					signOptions = append(signOptions, jws.WithDetachedPayload(payload))
					verifyOptions = append(verifyOptions, jws.WithDetachedPayload(payload))
					payload = nil
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
				Name: "JSON format",
				Input: []byte(`{
      "protected": "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19",
      "payload": "$.02",
      "signature": "A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY"
     }`),
			},
			{
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
				Name:  "JSON Format (b64 does not match)",
				Error: true,
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
				Name:  "Compact (detached payload)",
				Input: []byte(`eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY`),
				VerifyOptions: []jws.VerifyOption{
					jws.WithDetachedPayload(detached),
				},
			},
		}

		for _, tc := range testcases {
			tc := tc
			t.Run(tc.Name, func(t *testing.T) {
				options := tc.VerifyOptions
				options = append(options, jws.WithKey(jwa.HS256, key))
				payload, err := jws.Verify(tc.Input, options...)
				if tc.Error {
					require.Error(t, err, `jws.Verify should fail`)
					require.False(t, jws.IsVerificationError(err), `jws.IsVerifyError should return false`)
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

	verified, err := jws.Verify([]byte(signed), jws.WithKey(jwa.HS256, []byte("secret")))
	require.NoError(t, err, `jws.Verify should succeed`)
	require.Equal(t, expected, string(verified), `verified payload should match`)

	compact := strings.Join([]string{protected, payload, signature}, ".")
	verified, err = jws.Verify([]byte(compact), jws.WithKey(jwa.HS256, []byte("secret")))
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
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(set)
	}))
	defer srv.Close()

	payload := []byte("Lorem Ipsum")

	t.Run("Compact", func(t *testing.T) {
		testcases := []struct {
			Name         string
			Error        bool
			Query        string
			Fetcher      func() jwk.Fetcher
			FetchOptions func() []jwk.FetchOption
		}{
			{
				Name:  "Fail without whitelist",
				Error: true,
				FetchOptions: func() []jwk.FetchOption {
					return []jwk.FetchOption{jwk.WithHTTPClient(srv.Client())}
				},
			},
			{
				Name: "Success",
				FetchOptions: func() []jwk.FetchOption {
					return []jwk.FetchOption{
						jwk.WithFetchWhitelist(jwk.InsecureWhitelist{}),
						jwk.WithHTTPClient(srv.Client()),
					}
				},
			},
			{
				Name:  "Rejected by whitelist",
				Error: true,
				FetchOptions: func() []jwk.FetchOption {
					wl := jwk.NewMapWhitelist().Add(`https://github.com/lestrrat-go/jwx/v2`)
					return []jwk.FetchOption{
						jwk.WithFetchWhitelist(wl),
						jwk.WithHTTPClient(srv.Client()),
					}
				},
			},
			{
				Name: "JWKFetcher",
				Fetcher: func() jwk.Fetcher {
					c := jwk.NewCache(context.TODO())
					return jwk.FetchFunc(func(ctx context.Context, u string, options ...jwk.FetchOption) (jwk.Set, error) {
						var cacheopts []jwk.RegisterOption
						for _, option := range options {
							cacheopts = append(cacheopts, option)
						}
						cacheopts = append(cacheopts, jwk.WithHTTPClient(srv.Client()))
						cacheopts = append(cacheopts, jwk.WithFetchWhitelist(httprc.InsecureWhitelist{}))
						c.Register(u, cacheopts...)

						return c.Get(ctx, u)
					})
				},
			},
		}

		for _, tc := range testcases {
			tc := tc
			t.Run(tc.Name, func(t *testing.T) {
				hdr := jws.NewHeaders()
				u := srv.URL
				if tc.Query != "" {
					u += "?" + tc.Query
				}
				hdr.Set(jws.JWKSetURLKey, u)
				signed, err := jws.Sign(payload, jws.WithKey(jwa.RS256, key, jws.WithProtectedHeaders(hdr)))
				require.NoError(t, err, `jws.Sign should succeed`)

				var options []jwk.FetchOption
				if f := tc.FetchOptions; f != nil {
					options = append(options, f()...)
				}

				var fetcher jwk.Fetcher
				if f := tc.Fetcher; f != nil {
					fetcher = f()
				}
				decoded, err := jws.Verify(signed, jws.WithVerifyAuto(fetcher, options...))
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
		var keys []jwk.Key
		for i := 0; i < 3; i++ {
			key, err := jwxtest.GenerateRsaJwk()
			require.NoError(t, err, `jwxtest.GenerateRsaJwk should succeed`)
			key.Set(jwk.KeyIDKey, fmt.Sprintf(`used-%d`, i))
			keys = append(keys, key)
		}

		var unusedKeys []jwk.Key
		for i := 0; i < 2; i++ {
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
			require.Equal(t, pubkey.KeyID(), key.KeyID(), `key ID should be populated`)
			set.AddKey(pubkey)
		}
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(set)
		}))
		defer srv.Close()

		// Sign the payload using the three keys
		var signOptions = []jws.SignOption{jws.WithJSON()}
		for _, key := range keys {
			hdr := jws.NewHeaders()
			hdr.Set(jws.JWKSetURLKey, srv.URL)
			signOptions = append(signOptions, jws.WithKey(jwa.RS256, key, jws.WithProtectedHeaders(hdr)))
		}

		signed, err := jws.Sign(payload, signOptions...)
		require.NoError(t, err, `jws.SignMulti should succeed`)

		testcases := []struct {
			Name         string
			FetchOptions func() []jwk.FetchOption
			Error        bool
		}{
			{
				Name:  "Fail without whitelist",
				Error: true,
			},
			{
				Name: "Success",
				FetchOptions: func() []jwk.FetchOption {
					return []jwk.FetchOption{
						jwk.WithFetchWhitelist(jwk.InsecureWhitelist{}),
					}
				},
			},
			{
				Name:  "Rejected by whitelist",
				Error: true,
				FetchOptions: func() []jwk.FetchOption {
					wl := jwk.NewMapWhitelist().Add(`https://github.com/lestrrat-go/jwx/v2`)
					return []jwk.FetchOption{
						jwk.WithFetchWhitelist(wl),
					}
				},
			},
		}

		for _, tc := range testcases {
			tc := tc
			t.Run(tc.Name, func(t *testing.T) {
				m := jws.NewMessage()
				var options []jwk.FetchOption
				if fn := tc.FetchOptions; fn != nil {
					options = fn()
				}
				options = append(options, jwk.WithHTTPClient(srv.Client()))

				decoded, err := jws.Verify(signed, jws.WithVerifyAuto(nil, options...), jws.WithMessage(m))
				if tc.Error {
					require.Error(t, err, `jws.Verify should fail`)
				} else {
					if !assert.NoError(t, err, `jws.Verify should succeed`) {
						set, _ := jwk.Fetch(context.Background(), srv.URL, options...)
						{
							buf, _ := json.MarshalIndent(set, "", "  ")
							t.Logf("%s", buf)
						}
						return
					}
					require.Equal(t, payload, decoded, `decoded payload should match`)
					// XXX This actally doesn't really test much, but if there was anything
					// wrong, the process should have failed well before reaching here
					require.Equal(t, payload, m.Payload(), "message payload matches")
				}
			})
		}
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

	testcases := []struct {
		Name     string
		Key      interface{}
		Expected []jwa.SignatureAlgorithm
	}{
		{
			Name:     "Octet sequence",
			Key:      []byte("hello"),
			Expected: []jwa.SignatureAlgorithm{jwa.HS256, jwa.HS384, jwa.HS512},
		},
		{
			Name:     "rsa.PublicKey",
			Key:      rsa.PublicKey{},
			Expected: []jwa.SignatureAlgorithm{jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512},
		},
		{
			Name:     "*rsa.PublicKey",
			Key:      &rsa.PublicKey{},
			Expected: []jwa.SignatureAlgorithm{jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512},
		},
		{
			Name:     "jwk.RSAPublicKey",
			Key:      rsapubkey,
			Expected: []jwa.SignatureAlgorithm{jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512},
		},
		{
			Name:     "ecdsa.PublicKey",
			Key:      ecdsa.PublicKey{},
			Expected: []jwa.SignatureAlgorithm{jwa.ES256, jwa.ES384, jwa.ES512},
		},
		{
			Name:     "*ecdsa.PublicKey",
			Key:      &ecdsa.PublicKey{},
			Expected: []jwa.SignatureAlgorithm{jwa.ES256, jwa.ES384, jwa.ES512},
		},
		{
			Name:     "jwk.ECDSAPublicKey",
			Key:      ecdsapubkey,
			Expected: []jwa.SignatureAlgorithm{jwa.ES256, jwa.ES384, jwa.ES512},
		},
		{
			Name:     "rsa.PrivateKey",
			Key:      rsa.PrivateKey{},
			Expected: []jwa.SignatureAlgorithm{jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512},
		},
		{
			Name:     "*rsa.PrivateKey",
			Key:      &rsa.PrivateKey{},
			Expected: []jwa.SignatureAlgorithm{jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512},
		},
		{
			Name:     "jwk.RSAPrivateKey",
			Key:      rsapubkey,
			Expected: []jwa.SignatureAlgorithm{jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512},
		},
		{
			Name:     "ecdsa.PrivateKey",
			Key:      ecdsa.PrivateKey{},
			Expected: []jwa.SignatureAlgorithm{jwa.ES256, jwa.ES384, jwa.ES512},
		},
		{
			Name:     "*ecdsa.PrivateKey",
			Key:      &ecdsa.PrivateKey{},
			Expected: []jwa.SignatureAlgorithm{jwa.ES256, jwa.ES384, jwa.ES512},
		},
		{
			Name:     "jwk.ECDSAPrivateKey",
			Key:      ecdsaprivkey,
			Expected: []jwa.SignatureAlgorithm{jwa.ES256, jwa.ES384, jwa.ES512},
		},
		{
			Name:     "ed25519.PublicKey",
			Key:      ed25519.PublicKey(nil),
			Expected: []jwa.SignatureAlgorithm{jwa.EdDSA},
		},
		{
			Name:     "x25519.PublicKey",
			Key:      x25519.PublicKey(nil),
			Expected: []jwa.SignatureAlgorithm{jwa.EdDSA},
		},
	}

	for _, tc := range testcases {
		tc := tc

		if hasES256K {
			if strings.Contains(strings.ToLower(tc.Name), `ecdsa`) {
				tc.Expected = append(tc.Expected, jwa.ES256K)
			}
		}

		sort.Slice(tc.Expected, func(i, j int) bool {
			return tc.Expected[i].String() < tc.Expected[j].String()
		})
		t.Run(tc.Name, func(t *testing.T) {
			algs, err := jws.AlgorithmsForKey(tc.Key)
			require.NoError(t, err, `jws.AlgorithmsForKey should succeed`)

			sort.Slice(algs, func(i, j int) bool {
				return algs[i].String() < algs[j].String()
			})
			require.Equal(t, tc.Expected, algs, `results should match`)
		})
	}
}

func TestGH681(t *testing.T) {
	privkey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err, "failed to create private key")

	buf, err := jws.Sign(nil, jws.WithKey(jwa.RS256, privkey), jws.WithDetachedPayload([]byte("Lorem ipsum")))
	require.NoError(t, err, "failed to sign payload")

	t.Logf("%s", buf)

	_, err = jws.Verify(buf, jws.WithKey(jwa.RS256, &privkey.PublicKey), jws.WithDetachedPayload([]byte("Lorem ipsum")))
	require.NoError(t, err, "failed to verify JWS message")
}

func TestGH840(t *testing.T) {
	// Go 1.19+ panics if elliptic curve operations are called against
	// a point that's _NOT_ on the curve
	untrustedJWK := []byte(`{
		"kty": "EC",
		"crv": "P-256",
		"x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqx7D4",
		"y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
		"d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
	}`)

	// Parse, serialize, slice and dice JWKs!
	privkey, err := jwk.ParseKey(untrustedJWK)
	require.NoError(t, err, `jwk.ParseKey should succeed`)

	pubkey, err := jwk.PublicKeyOf(privkey)
	require.NoError(t, err, `jwk.PublicKeyOf should succeed`)

	tok, err := jwt.NewBuilder().
		Issuer(`github.com/lestrrat-go/jwx`).
		IssuedAt(time.Now()).
		Build()
	require.NoError(t, err, `jwt.NewBuilder should succeed`)

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, privkey))
	require.NoError(t, err, `jwt.Sign should succeed`)

	_, err = jwt.Parse(signed, jwt.WithKey(jwa.ES256, pubkey))
	require.Error(t, err, `jwt.Parse should FAIL`) // pubkey's X/Y is not on the curve
}

func TestGH888(t *testing.T) {
	// This should fail because we're passing multiple keys (i.e. multiple signatures)
	// and yet we haven't specified JSON serialization
	_, err := jws.Sign([]byte(`foo`), jws.WithInsecureNoSignature(), jws.WithKey(jwa.HS256, []byte(`bar`)))
	require.Error(t, err, `jws.Sign with multiple keys (including alg=none) should fail`)

	// This should pass because we can now have multiple signaures with JSON serialization
	signed, err := jws.Sign([]byte(`foo`), jws.WithInsecureNoSignature(), jws.WithKey(jwa.HS256, []byte(`bar`)), jws.WithJSON())
	require.NoError(t, err, `jws.Sign should succeed`)

	message, err := jws.Parse(signed)
	require.NoError(t, err, `jws.Parse should succeed`)

	// Look for alg=none signature
	var foundNoSignature bool
	for _, sig := range message.Signatures() {
		if sig.ProtectedHeaders().Algorithm() != jwa.NoSignature {
			continue
		}

		require.Nil(t, sig.Signature(), `signature must be nil for alg=none`)
		foundNoSignature = true
	}
	require.True(t, foundNoSignature, `signature with no signature was found`)

	_, err = jws.Verify(signed)
	require.Error(t, err, `jws.Verify should fail`)

	_, err = jws.Verify(signed, jws.WithKey(jwa.NoSignature, nil))
	require.Error(t, err, `jws.Verify should fail`)

	// Note: you can't do jws.Verify(..., jws.WithInsecureNoSignature())

	verified, err := jws.Verify(signed, jws.WithKey(jwa.HS256, []byte(`bar`)))
	require.NoError(t, err, `jws.Verify should succeed`)
	require.Equal(t, []byte(`foo`), verified)
}

// Some stuff required for testing #910
// The original code used an external library to sign/verify, but here
// we just use a simple SHA256 digest here so that we don't force
// users to download an optional dependency
type s256SignerVerifier struct{}

const sha256Algo jwa.SignatureAlgorithm = "SillyTest256"

func (s256SignerVerifier) Algorithm() jwa.SignatureAlgorithm {
	return sha256Algo
}

func (s256SignerVerifier) Sign(payload []byte, _ interface{}) ([]byte, error) {
	h := sha256.Sum256(payload)
	return h[:], nil
}

func (s256SignerVerifier) Verify(payload, signature []byte, _ interface{}) error {
	h := sha256.Sum256(payload)
	if !bytes.Equal(h[:], signature) {
		return errors.New("invalid signature")
	}
	return nil
}

func TestGH910(t *testing.T) {
	// Note: This has global effect. You can't run this in parallel with other tests
	jws.RegisterSigner(sha256Algo, jws.SignerFactoryFn(func() (jws.Signer, error) {
		return s256SignerVerifier{}, nil
	}))
	defer jws.UnregisterSigner(sha256Algo)

	jws.RegisterVerifier(sha256Algo, jws.VerifierFactoryFn(func() (jws.Verifier, error) {
		return s256SignerVerifier{}, nil
	}))
	defer jws.UnregisterVerifier(sha256Algo)
	defer jwa.UnregisterSignatureAlgorithm(sha256Algo)

	var sa jwa.SignatureAlgorithm
	require.NoError(t, sa.Accept(sha256Algo.String()), `jwa.SignatureAlgorithm.Accept should succeed`)

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

	jws.RegisterSigner(sha256Algo, jws.SignerFactoryFn(func() (jws.Signer, error) {
		return s256SignerVerifier{}, nil
	}))

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

			key, err := jwk.FromRaw(rawKey)
			require.NoError(t, err, `jwk.FromRaw should succeed`)

			pubkey, _ := key.PublicKey()

			signed, err := jws.Sign([]byte("Lorem Ipsum"), jws.WithKey(jwa.ES256, key))
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

					i := bytes.LastIndexByte(signed, '.')
					modified := append(signed[:i+1], base64.Encode(unpaddedSig)...)
					t.Logf("JWS payload with unpadded signature: %q", modified)

					// jws.Verify for sanity
					verified, err := jws.Verify(modified, jws.WithKey(jwa.ES256, pubkey))
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
	payload, err := jws.Verify([]byte(padded), jws.WithKey(jwa.ES256, pubKey))
	require.NoError(t, err, `jws.Verify should succeed`)
	require.Equal(t, "Lorem Ipsum", string(payload))

	// Should fail
	_, err = jws.Verify([]byte(unpadded), jws.WithKey(jwa.ES256, pubKey))
	require.Error(t, err, `jws.Verify should fail`)
}

func TestValidateKey(t *testing.T) {
	privKey, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err, `jwxtest.GenerateRsaJwk should succeed`)

	signed, err := jws.Sign([]byte("Lorem Ipsum"), jws.WithKey(jwa.RS256, privKey), jws.WithValidateKey(true))
	require.NoError(t, err, `jws.Sign should succeed`)

	// This should fail because D is empty
	require.NoError(t, privKey.Set(jwk.RSADKey, []byte(nil)), `jwk.Set should succeed`)
	_, err = jws.Sign([]byte("Lorem Ipsum"), jws.WithKey(jwa.RS256, privKey), jws.WithValidateKey(true))
	require.Error(t, err, `jws.Sign should fail`)

	pubKey, err := jwk.PublicKeyOf(privKey)
	require.NoError(t, err, `jwk.PublicKeyOf should succeed`)

	n := pubKey.(jwk.RSAPublicKey).N()

	// Set N to an empty value
	require.NoError(t, pubKey.Set(jwk.RSANKey, []byte(nil)), `jwk.Set should succeed`)

	// This is going to fail regardless, because the public key is now
	// invalid (empty N), but we want to make sure that it fails because
	// of the validation failing
	_, err = jws.Verify(signed, jws.WithKey(jwa.RS256, pubKey), jws.WithValidateKey(true))
	require.Error(t, err, `jws.Verify should fail`)
	require.True(t, jwk.IsKeyValidationError(err), `jwk.IsKeyValidationError should return true`)

	// The following should now succeed, because N has been reinstated
	require.NoError(t, pubKey.Set(jwk.RSANKey, n), `jwk.Set should succeed`)
	_, err = jws.Verify(signed, jws.WithKey(jwa.RS256, pubKey), jws.WithValidateKey(true))
	require.NoError(t, err, `jws.Verify should succeed`)
}
