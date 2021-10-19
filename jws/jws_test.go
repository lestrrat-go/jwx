package jws_test

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha512"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/internal/base64"
	"github.com/lestrrat-go/jwx/internal/json"
	"github.com/lestrrat-go/jwx/internal/jwxtest"
	"github.com/lestrrat-go/jwx/x25519"
	"github.com/pkg/errors"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/stretchr/testify/assert"
)

const examplePayload = `{"iss":"joe",` + "\r\n" + ` "exp":1300819380,` + "\r\n" + ` "http://example.com/is_root":true}`
const exampleCompactSerialization = `eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`
const badValue = "%badvalue%"

func TestParseReader(t *testing.T) {
	t.Parallel()
	t.Run("Empty []byte", func(t *testing.T) {
		t.Parallel()
		_, err := jws.Parse(nil)
		if !assert.Error(t, err, "Parsing an empty byte slice should result in an error") {
			return
		}
	})
	t.Run("Empty bytes.Buffer", func(t *testing.T) {
		t.Parallel()
		_, err := jws.ParseReader(&bytes.Buffer{})
		if !assert.Error(t, err, "Parsing an empty buffer should result in an error") {
			return
		}
	})
	t.Run("Compact missing parts", func(t *testing.T) {
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
			if !assert.Error(t, err, "Parsing compact serialization with less than 3 parts should be an error") {
				return
			}
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
			if !assert.Error(t, err, "Parsing compact serialization with bad header should be an error") {
				return
			}
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
			if !assert.Error(t, err, "Parsing compact serialization with bad payload should be an error") {
				return
			}
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
			if !assert.Error(t, err, "Parsing compact serialization with bad signature should be an error") {
				return
			}
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

func (es *dummyECDSACryptoSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// The implementation is the same as ecdsaCryptoSigner.
	// This is just here to test the interface conversion
	r, s, err := ecdsa.Sign(rand, es.raw, digest)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign payload using ecdsa")
	}

	curveBits := es.raw.Curve.Params().BitSize
	keyBytes := curveBits / 8
	// Curve bits do not need to be a multiple of 8.
	if curveBits%8 > 0 {
		keyBytes++
	}

	rBytes := r.Bytes()
	rBytesPadded := make([]byte, keyBytes)
	copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

	sBytes := s.Bytes()
	sBytesPadded := make([]byte, keyBytes)
	copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)

	out := append(rBytesPadded, sBytesPadded...)
	return out, nil
}

var _ crypto.Signer = &dummyECDSACryptoSigner{}

func testRoundtrip(t *testing.T, payload []byte, alg jwa.SignatureAlgorithm, signKey interface{}, keys map[string]interface{}) {
	t.Helper()

	jwkKey, err := jwk.New(signKey)
	if !assert.NoError(t, err, `jwk.New should succeed`) {
		return
	}
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
			signed, err := jws.Sign(payload, alg, key.Key)
			if !assert.NoError(t, err, "jws.Sign should succeed") {
				return
			}

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
					if !assert.NoError(t, err, "(%s) %s is successful", alg, name) {
						return
					}

					if !assert.Equal(t, payload, m.Payload(), "(%s) %s: Payload is decoded", alg, name) {
						return
					}
				})
			}

			for name, testKey := range keys {
				name := name
				testKey := testKey
				t.Run(name, func(t *testing.T) {
					verified, err := jws.Verify(signed, alg, testKey)
					if !assert.NoError(t, err, "(%s) Verify is successful", alg) {
						return
					}

					if !assert.Equal(t, payload, verified, "(%s) Verified payload is the same", alg) {
						return
					}
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
		jwkKey, _ := jwk.New(sharedkey)
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
		if !assert.NoError(t, err, "ECDSA key generated") {
			return
		}
		jwkKey, _ := jwk.New(key.PublicKey)
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
		if !assert.NoError(t, err, "RSA key generated") {
			return
		}
		jwkKey, _ := jwk.New(key.PublicKey)
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
		if !assert.NoError(t, err, "ed25519 key generated") {
			return
		}
		pubkey := key.Public()
		jwkKey, _ := jwk.New(pubkey)
		keys := map[string]interface{}{
			"Verify(ed25519.Public())":  pubkey,
			"Verify(*ed25519.Public())": &pubkey,
			"Verify(jwk.Key)":           jwkKey,
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
		var options []jws.Option
		for _, alg := range hmacAlgorithms {
			signer, err := jws.NewSigner(alg)
			if !assert.NoError(t, err, `jws.NewSigner should succeed`) {
				return
			}
			options = append(options, jws.WithSigner(signer, sharedkey, nil, nil))
		}
		var err error
		signed, err = jws.SignMulti(payload, options...)
		if !assert.NoError(t, err, `jws.SignMulti should succeed`) {
			return
		}
	})
	for _, alg := range hmacAlgorithms {
		alg := alg
		t.Run("Verify "+alg.String(), func(t *testing.T) {
			verified, err := jws.Verify(signed, alg, sharedkey)
			if !assert.NoError(t, err, "Verify succeeded") {
				return
			}

			if !assert.Equal(t, payload, verified, "verified payload matches") {
				return
			}
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
		if !assert.NoError(t, err, "HMAC base64 decoded successful") {
			return
		}

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
		if !assert.NoError(t, err, "HMAC signer created successfully") {
			return
		}

		signature, err := sign.Sign(signingInput, hmacKeyDecoded)
		if !assert.NoError(t, err, "PayloadSign is successful") {
			return
		}
		sigbuf := base64.Encode(signature)

		encoded := bytes.Join(
			[][]byte{
				signingInput,
				sigbuf,
			},
			[]byte{'.'},
		)
		if !assert.Equal(t, expected, string(encoded), "generated compact serialization should match") {
			return
		}

		msg, err := jws.ParseReader(bytes.NewReader(encoded))
		if !assert.NoError(t, err, "Parsing compact encoded serialization succeeds") {
			return
		}

		signatures := msg.Signatures()
		if !assert.Len(t, signatures, 1, `there should be exactly one signature`) {
			return
		}

		algorithm := signatures[0].ProtectedHeaders().Algorithm()
		if algorithm != jwa.HS256 {
			t.Fatal("Algorithm in header does not match")
		}

		v, err := jws.NewVerifier(jwa.HS256)
		if !assert.NoError(t, err, "HmacVerify created") {
			return
		}

		if !assert.NoError(t, v.Verify(signingInput, signature, hmacKeyDecoded), "Verify succeeds") {
			return
		}
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
		if !assert.NoError(t, json.Unmarshal(hdr, standardHeaders), `parsing headers should succeed`) {
			return
		}

		alg := standardHeaders.Algorithm()

		jwkKey, err := jwk.ParseKey([]byte(jwksrc))
		if err != nil {
			t.Fatal("Failed to parse JWK")
		}
		var key interface{}
		if !assert.NoError(t, jwkKey.Raw(&key), `jwk.Raw should succeed`) {
			return
		}
		var jwsCompact []byte
		jwsCompact, err = jws.Sign(jwsPayload, alg, key)
		if err != nil {
			t.Fatal("Failed to sign message")
		}

		// Verify with standard ecdsa library
		_, _, jwsSignature, err := jws.SplitCompact(jwsCompact)
		if err != nil {
			t.Fatal("Failed to split compact JWT")
		}

		decodedJwsSignature, err := base64.Decode(jwsSignature)
		if !assert.NoError(t, err, `base64.Decode should succeed`) {
			return
		}
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
		if !assert.True(t, ecdsa.Verify(&ecdsaPrivateKey.PublicKey, hashed512[:], r, s), "ecdsa.Verify should succeed") {
			return
		}

		// Verify with API library
		publicKey, err := jwk.PublicRawKeyOf(key)
		if !assert.NoError(t, err, `jwk.PublicRawKeyOf should succeed`) {
			return
		}
		verifiedPayload, err := jws.Verify(jwsCompact, alg, publicKey)
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

		privkey := jwk.NewRSAPrivateKey()
		if !assert.NoError(t, json.Unmarshal([]byte(jwksrc), privkey), `parsing jwk should be successful`) {
			return
		}

		var rawkey rsa.PrivateKey
		if !assert.NoError(t, privkey.Raw(&rawkey), `obtaining raw key should succeed`) {
			return
		}

		sign, err := jws.NewSigner(jwa.RS256)
		if !assert.NoError(t, err, "RsaSign created successfully") {
			return
		}

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
		if !assert.NoError(t, err, "PayloadSign is successful") {
			return
		}
		sigbuf := base64.Encode(signature)

		encoded := bytes.Join(
			[][]byte{
				signingInput,
				sigbuf,
			},
			[]byte{'.'},
		)

		if !assert.Equal(t, expected, string(encoded), "generated compact serialization should match") {
			return
		}

		msg, err := jws.ParseReader(bytes.NewReader(encoded))
		if !assert.NoError(t, err, "Parsing compact encoded serialization succeeds") {
			return
		}

		signatures := msg.Signatures()
		if !assert.Len(t, signatures, 1, `there should be exactly one signature`) {
			return
		}

		algorithm := signatures[0].ProtectedHeaders().Algorithm()
		if algorithm != jwa.RS256 {
			t.Fatal("Algorithm in header does not match")
		}

		v, err := jws.NewVerifier(jwa.RS256)
		if !assert.NoError(t, err, "Verify created") {
			return
		}

		if !assert.NoError(t, v.Verify(signingInput, signature, rawkey.PublicKey), "Verify succeeds") {
			return
		}
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
		privkey := jwk.NewECDSAPrivateKey()
		if !assert.NoError(t, json.Unmarshal([]byte(jwksrc), privkey), `parsing jwk should succeed`) {
			return
		}

		var rawkey ecdsa.PrivateKey
		if !assert.NoError(t, privkey.Raw(&rawkey), `obtaining raw key should succeed`) {
			return
		}

		signer, err := jws.NewSigner(jwa.ES256)
		if !assert.NoError(t, err, "RsaSign created successfully") {
			return
		}

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
		if !assert.NoError(t, err, "PayloadSign is successful") {
			return
		}
		sigbuf := base64.Encode(signature)
		if !assert.NoError(t, err, "base64 encode successful") {
			return
		}

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
		if !assert.NoError(t, err, "Parsing compact encoded serialization succeeds") {
			return
		}

		signatures := msg.Signatures()
		if !assert.Len(t, signatures, 1, `there should be exactly one signature`) {
			return
		}

		algorithm := signatures[0].ProtectedHeaders().Algorithm()
		if algorithm != jwa.ES256 {
			t.Fatal("Algorithm in header does not match")
		}

		v, err := jws.NewVerifier(jwa.ES256)
		if !assert.NoError(t, err, "EcdsaVerify created") {
			return
		}
		if !assert.NoError(t, v.Verify(signingInput, signature, rawkey.PublicKey), "Verify succeeds") {
			return
		}
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
		if !assert.NoError(t, err, "Expected Signature decode successful") {
			return
		}

		privkey := jwk.NewOKPPrivateKey()
		if !assert.NoError(t, json.Unmarshal([]byte(jwksrc), privkey), `parsing jwk should succeed`) {
			return
		}

		var rawkey ed25519.PrivateKey
		if !assert.NoError(t, privkey.Raw(&rawkey), `obtaining raw key should succeed`) {
			return
		}

		signer, err := jws.NewSigner(jwa.EdDSA)
		if !assert.NoError(t, err, "EdDSASign created successfully") {
			return
		}

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
		if !assert.NoError(t, err, "PayloadSign is successful") {
			return
		}
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
		if !assert.NoError(t, err, "Parsing compact encoded serialization succeeds") {
			return
		}

		signatures := msg.Signatures()
		if !assert.Len(t, signatures, 1, `there should be exactly one signature`) {
			return
		}

		algorithm := signatures[0].ProtectedHeaders().Algorithm()
		if algorithm != jwa.EdDSA {
			t.Fatal("Algorithm in header does not match")
		}

		v, err := jws.NewVerifier(jwa.EdDSA)
		if !assert.NoError(t, err, "EcdsaVerify created") {
			return
		}
		if !assert.NoError(t, v.Verify(signingInput, signature, rawkey.Public()), "Verify succeeds") {
			return
		}
		if !assert.Equal(t, signature, expectedDecoded, "signatures match") {
			return
		}
	})
	t.Run("UnsecuredCompact", func(t *testing.T) {
		t.Parallel()
		s := `eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.`

		m, err := jws.ParseReader(strings.NewReader(s))
		if !assert.NoError(t, err, "Parsing compact serialization") {
			return
		}

		{
			v := map[string]interface{}{}
			if !assert.NoError(t, json.Unmarshal(m.Payload(), &v), "Unmarshal payload") {
				return
			}
			if !assert.Equal(t, v["iss"], "joe", "iss matches") {
				return
			}
			if !assert.Equal(t, int(v["exp"].(float64)), 1300819380, "exp matches") {
				return
			}
			if !assert.Equal(t, v["http://example.com/is_root"], true, "'http://example.com/is_root' matches") {
				return
			}
		}

		if !assert.Len(t, m.Signatures(), 1, "There should be 1 signature") {
			return
		}

		signatures := m.Signatures()
		algorithm := signatures[0].ProtectedHeaders().Algorithm()
		if algorithm != jwa.NoSignature {
			t.Fatal("Algorithm in header does not match")
		}

		if !assert.Empty(t, signatures[0].Signature(), "Signature should be empty") {
			return
		}
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
		if !assert.NoError(t, err, "Unmarshal complete json serialization") {
			return
		}

		if !assert.Len(t, m.Signatures(), 2, "There should be 2 signatures") {
			return
		}

		sigs := m.LookupSignature("2010-12-29")
		if !assert.Len(t, sigs, 1, "There should be 1 signature with kid = '2010-12-29'") {
			return
		}
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
		if !assert.NoError(t, err, "Unmarshal complete json serialization") {
			return
		}
		if len(m.Signatures()) != 1 {
			t.Fatal("There should be 1 signature")
		}

		sigs := m.LookupSignature("e9bc097a-ce51-4036-9562-d2ade882db0d")
		if !assert.Len(t, sigs, 1, "There should be 1 signature with kid = '2010-12-29'") {
			return
		}
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
		if !assert.NoError(t, err, "Parsing flattened json serialization") {
			return
		}

		if !assert.Len(t, m.Signatures(), 1, "There should be 1 signature") {
			return
		}

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
					if !assert.NoError(t, err, "SplitCompact should succeed") {
						return
					}
					if !assert.Len(t, x, size, "Length of header") {
						return
					}
					if !assert.Len(t, y, size, "Length of payload") {
						return
					}
					if !assert.Len(t, z, size, "Length of signature") {
						return
					}
				}
			})
		}
	})
}

func TestPublicHeaders(t *testing.T) {
	key, err := jwxtest.GenerateRsaKey()
	if !assert.NoError(t, err, "GenerateKey should succeed") {
		return
	}

	signer, err := jws.NewSigner(jwa.RS256)
	if !assert.NoError(t, err, "jws.NewSigner should succeed") {
		return
	}
	_ = signer // TODO

	pubkey := key.PublicKey
	pubjwk, err := jwk.New(&pubkey)
	if !assert.NoError(t, err, "NewRsaPublicKey should succeed") {
		return
	}
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

	pubkey := jwk.NewECDSAPublicKey()
	if !assert.NoError(t, json.Unmarshal([]byte(jwksrc), pubkey), `parsing jwk should be successful`) {
		return
	}

	var rawkey ecdsa.PublicKey
	if !assert.NoError(t, pubkey.Raw(&rawkey), `obtaining raw key should succeed`) {
		return
	}

	v, err := jws.NewVerifier(jwa.ES384)
	if !assert.NoError(t, err, "EcdsaVerify created") {
		return
	}

	protected, payload, signature, err := jws.SplitCompact([]byte(incoming))
	if !assert.NoError(t, err, `jws.SplitCompact should succeed`) {
		return
	}

	var buf bytes.Buffer
	buf.Write(protected)
	buf.WriteByte('.')
	buf.Write(payload)

	decodedSignature, err := base64.Decode(signature)
	if !assert.NoError(t, err, `decoding signature should succeed`) {
		return
	}

	if !assert.NoError(t, v.Verify(buf.Bytes(), decodedSignature, rawkey), "Verify succeeds") {
		return
	}
}

func TestReadFile(t *testing.T) {
	t.Parallel()

	f, err := ioutil.TempFile("", "test-read-file-*.jws")
	if !assert.NoError(t, err, `ioutil.TempFile should succeed`) {
		return
	}
	defer f.Close()

	fmt.Fprintf(f, "%s", exampleCompactSerialization)

	if _, err := jws.ReadFile(f.Name()); !assert.NoError(t, err, `jws.ReadFile should succeed`) {
		return
	}
}

func TestVerifySet(t *testing.T) {
	t.Parallel()
	const payload = "Lorem ipsum"

	makeSet := func(privkey jwk.Key) jwk.Set {
		set := jwk.NewSet()
		k1, _ := jwk.New([]byte("abracadavra"))
		set.Add(k1)
		k2, _ := jwk.New([]byte("opensasame"))
		set.Add(k2)
		pubkey, _ := jwk.PublicKeyOf(privkey)
		pubkey.Set(jwk.AlgorithmKey, jwa.RS256)
		set.Add(pubkey)
		return set
	}

	for _, useJSON := range []bool{true, false} {
		useJSON := useJSON
		t.Run(fmt.Sprintf("useJSON=%t", useJSON), func(t *testing.T) {
			t.Parallel()
			t.Run(`match via "alg"`, func(t *testing.T) {
				t.Parallel()
				key, err := jwxtest.GenerateRsaJwk()
				if !assert.NoError(t, err, "jwxtest.GenerateJwk should succeed") {
					return
				}

				set := makeSet(key)
				signed, err := jws.Sign([]byte(payload), jwa.RS256, key)
				if !assert.NoError(t, err, `jws.Sign should succeed`) {
					return
				}
				if useJSON {
					m, err := jws.Parse(signed)
					if !assert.NoError(t, err, `jws.Parse should succeed`) {
						return
					}
					signed, err = json.Marshal(m)
					if !assert.NoError(t, err, `json.Marshal should succeed`) {
						return
					}
				}

				verified, err := jws.VerifySet(signed, set)
				if !assert.NoError(t, err, `jws.VerifySet should succeed`) {
					return
				}
				if !assert.Equal(t, []byte(payload), verified, `payload should match`) {
					return
				}
			})
			t.Run(`match via "kid"`, func(t *testing.T) {
				t.Parallel()

				key, err := jwxtest.GenerateRsaJwk()
				if !assert.NoError(t, err, "jwxtest.GenerateJwk should succeed") {
					return
				}
				key.Set(jwk.KeyIDKey, `mykey`)

				set := makeSet(key)
				signed, err := jws.Sign([]byte(payload), jwa.RS256, key)
				if !assert.NoError(t, err, `jws.Sign should succeed`) {
					return
				}
				if useJSON {
					m, err := jws.Parse(signed)
					if !assert.NoError(t, err, `jws.Parse should succeed`) {
						return
					}
					signed, err = json.Marshal(m)
					if !assert.NoError(t, err, `json.Marshal should succeed`) {
						return
					}
				}

				verified, err := jws.VerifySet(signed, set)
				if !assert.NoError(t, err, `jws.VerifySet should succeed`) {
					return
				}
				if !assert.Equal(t, []byte(payload), verified, `payload should match`) {
					return
				}
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
	if !assert.NoError(t, err, `jwxtest.GenerateRsaJwk() should succeed`) {
		return
	}

	hdrs := jws.NewHeaders()
	hdrs.Set(`x-birthday`, string(bdaybytes))

	signed, err := jws.Sign([]byte(payload), jwa.RS256, privkey, jws.WithHeaders(hdrs))
	if !assert.NoError(t, err, `jws.Sign should succeed`) {
		return
	}

	t.Run("jws.Parse + json.Unmarshal", func(t *testing.T) {
		msg, err := jws.Parse(signed)
		if !assert.NoError(t, err, `jws.Parse should succeed`) {
			return
		}

		v, ok := msg.Signatures()[0].ProtectedHeaders().Get(`x-birthday`)
		if !assert.True(t, ok, `msg.Signatures()[0].ProtectedHeaders().Get("x-birthday") should succeed`) {
			return
		}

		if !assert.Equal(t, expected, v, `values should match`) {
			return
		}

		// Create JSON from jws.Message
		buf, err := json.Marshal(msg)
		if !assert.NoError(t, err, `json.Marshal should succeed`) {
			return
		}

		var msg2 jws.Message
		if !assert.NoError(t, json.Unmarshal(buf, &msg2), `json.Unmarshal should succeed`) {
			return
		}

		v, ok = msg2.Signatures()[0].ProtectedHeaders().Get(`x-birthday`)
		if !assert.True(t, ok, `msg2.Signatures()[0].ProtectedHeaders().Get("x-birthday") should succeed`) {
			return
		}

		if !assert.Equal(t, expected, v, `values should match`) {
			return
		}
	})
}

func TestWithMessage(t *testing.T) {
	key, err := jwxtest.GenerateRsaKey()
	if !assert.NoError(t, err, "jwxtest.Generate should succeed") {
		return
	}

	const text = "hello, world"
	signed, err := jws.Sign([]byte(text), jwa.RS256, key)
	if !assert.NoError(t, err, `jws.Sign should succeed`) {
		return
	}

	m := jws.NewMessage()
	payload, err := jws.Verify(signed, jwa.RS256, key.PublicKey, jws.WithMessage(m))
	if !assert.NoError(t, err, `jws.Verify should succeed`) {
		return
	}
	if !assert.Equal(t, payload, []byte(text), `jws.Verify should produce the correct payload`) {
		return
	}

	parsed, err := jws.Parse(signed)
	if !assert.NoError(t, err, `jws.Parse should succeed`) {
		return
	}

	// The result of using jws.WithMessage should match the result of jws.Parse
	buf1, _ := json.Marshal(m)
	buf2, _ := json.Marshal(parsed)

	if !assert.Equal(t, buf1, buf2, `result of jws.PArse and jws.Verify(..., jws.WithMessage()) should match`) {
		return
	}
}

func TestRFC7797(t *testing.T) {
	const keysrc = `{"kty":"oct",
      "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
     }`
	detached := []byte(`$.02`)

	key, err := jwk.ParseKey([]byte(keysrc))
	if !assert.NoError(t, err, `jwk.Parse should succeed`) {
		return
	}

	t.Run("Invalid payload when b64 = false", func(t *testing.T) {
		const payload = `$.02`
		hdrs := jws.NewHeaders()
		hdrs.Set("b64", false)
		hdrs.Set("crit", "b64")

		_, err := jws.Sign([]byte(payload), jwa.HS256, key, jws.WithHeaders(hdrs))
		if !assert.Error(t, err, `jws.Sign should fail`) {
			return
		}
	})
	t.Run("Roundtrip", func(t *testing.T) {
		const payload = `hell0w0r1d`
		hdrs := jws.NewHeaders()
		hdrs.Set("b64", false)
		hdrs.Set("crit", "b64")

		signed, err := jws.Sign([]byte(payload), jwa.HS256, key, jws.WithHeaders(hdrs))
		if !assert.NoError(t, err, `jws.Sign should succeed`) {
			return
		}

		verified, err := jws.Verify(signed, jwa.HS256, key)
		if !assert.NoError(t, err, `jws.Verify should succeed`) {
			return
		}

		if !assert.Equal(t, []byte(payload), verified, `payload should match`) {
			return
		}
	})

	t.Run("Verify", func(t *testing.T) {
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
				payload, err := jws.Verify(tc.Input, jwa.HS256, key, tc.VerifyOptions...)
				if tc.Error {
					if !assert.Error(t, err, `jws.Verify should fail`) {
						return
					}
				} else {
					if !assert.NoError(t, err, `jws.Verify should succeed`) {
						return
					}
					if !assert.Equal(t, detached, payload, `payload should match`) {
						return
					}
				}
			})
		}
	})
}

func TestAlgorithmsForKey(t *testing.T) {
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
			Key:      jwk.NewRSAPublicKey(),
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
			Key:      jwk.NewECDSAPublicKey(),
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
			Key:      jwk.NewRSAPrivateKey(),
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
			Key:      jwk.NewECDSAPrivateKey(),
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
		sort.Slice(tc.Expected, func(i, j int) bool {
			return tc.Expected[i].String() < tc.Expected[j].String()
		})
		t.Run(tc.Name, func(t *testing.T) {
			algs, err := jws.AlgorithmsForKey(tc.Key)
			if !assert.NoError(t, err, `jws.AlgorithmsForKey should succeed`) {
				return
			}

			sort.Slice(algs, func(i, j int) bool {
				return algs[i].String() < algs[j].String()
			})
			if !assert.Equal(t, tc.Expected, algs, `results should match`) {
				return
			}
		})
	}
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

	verified, err := jws.Verify([]byte(signed), jwa.HS256, []byte("secret"))
	if !assert.NoError(t, err, `jws.Verify should succeed`) {
		return
	}
	if !assert.Equal(t, expected, string(verified), `verified payload should match`) {
		return
	}

	compact := strings.Join([]string{protected, payload, signature}, ".")
	verified, err = jws.Verify([]byte(compact), jwa.HS256, []byte("secret"))
	if !assert.NoError(t, err, `jws.Verify should succeed`) {
		return
	}
	if !assert.Equal(t, expected, string(verified), `verified payload should match`) {
		return
	}
}
