package jwt_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/lestrrat-go/jwx/v4/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v4/internal/tokens"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"
	"github.com/lestrrat-go/jwx/v4/jwk"
	ourecdsa "github.com/lestrrat-go/jwx/v4/jwk/ecdsa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jws/jwsbb"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/lestrrat-go/jwx/v4/jwt/internal/types"
	"github.com/stretchr/testify/require"
)

/* This is commented out, because it is intended to cause compilation errors */
/*
func TestOption(t *testing.T) {
	var p jwt.ParseOption
	var v jwt.ValidateOption
	var o jwt.Option
	p = o // should be error
	v = o // should be error
	_ = p
	_ = v
}
*/

func TestToken_Field(t *testing.T) {
	tok, _ := jwt.NewBuilder().
		Issuer("github.com/lestrrat-go/jwx").
		IssuedAt(time.Now().Round(0)).
		Expiration(time.Now().Add(time.Hour * 24)).
		Build()

	for _, name := range []string{`aud`, `unknown`} {
		_, ok := tok.Field(name)
		require.False(t, ok, `tok.Field should return false for unset claim %q`, name)
	}

	for _, name := range []string{`iss`, `exp`} {
		v, ok := tok.Field(name)
		require.True(t, ok, `tok.Field should return true for set claim %q`, name)
		require.NotNil(t, v, `tok.Field value should not be nil for %q`, name)
	}
}

func TestToken_Parse(t *testing.T) {
	t.Parallel()

	alg := jwa.RS256()

	key, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err, `jwxtest.GenerateRsaKey should succeed`)
	t1 := jwt.New()
	signed, err := jwt.Sign(t1, jwt.WithKey(alg, key))
	require.NoError(t, err, `jwt.Sign should succeed`)
	t.Logf("%s", signed)

	t.Run("Parse (no signature verification)", func(t *testing.T) {
		t.Parallel()
		t2, err := jwt.ParseInsecure(signed)
		require.NoError(t, err, `jwt.Parse should succeed`)
		require.True(t, jwt.Equal(t1, t2), `t1 == t2`)
	})
	t.Run("ParseString (no signature verification)", func(t *testing.T) {
		t.Parallel()
		t2, err := jwt.ParseString(string(signed), jwt.WithVerify(false), jwt.WithValidate(false))
		require.NoError(t, err, `jwt.ParseString should succeed`)
		require.True(t, jwt.Equal(t1, t2), `t1 == t2`)
	})
	t.Run("ParseReader (no signature verification)", func(t *testing.T) {
		t.Parallel()
		t2, err := jwt.ParseReader(bytes.NewReader(signed), jwt.WithVerify(false), jwt.WithValidate(false))
		require.NoError(t, err, `jwt.ParseReader should succeed`)
		require.True(t, jwt.Equal(t1, t2), `t1 == t2`)
	})
	t.Run("Parse (correct signature key)", func(t *testing.T) {
		t.Parallel()
		t2, err := jwt.Parse(signed, jwt.WithKey(alg, &key.PublicKey))
		require.NoError(t, err, `jwt.Parse should succeed`)
		require.True(t, jwt.Equal(t1, t2), `t1 == t2`)
	})
	t.Run("parse (wrong signature algorithm)", func(t *testing.T) {
		t.Parallel()
		_, err := jwt.Parse(signed, jwt.WithKey(jwa.RS512(), &key.PublicKey))
		require.Error(t, err, `jwt.Parse should fail`)
		require.True(t, errors.Is(err, jwt.ParseError{}), `err should be a parse error`)
		require.True(t, errors.Is(err, jws.VerifyError()), `err should be a verify error`)
		require.True(t, errors.Is(err, jws.VerificationError()), `err should be a verification error`)
	})
	t.Run("parse (wrong signature key)", func(t *testing.T) {
		t.Parallel()
		pubkey := key.PublicKey
		pubkey.E = 0 // bogus value
		_, err := jwt.Parse(signed, jwt.WithKey(alg, &pubkey))
		require.Error(t, err, `jwt.Parse should fail`)
		require.True(t, errors.Is(err, jwt.ParseError{}), `err should be a parse error`)
		require.True(t, errors.Is(err, jws.VerifyError()), `err should be a verify error`)
		require.True(t, errors.Is(err, jws.VerificationError()), `err should be a verification error`)
	})
}

func TestStrictBase64Encoding(t *testing.T) {
	t.Parallel()

	alg := jwa.HS256()
	key := []byte("supersecret-key-for-testing-only")

	tok := jwt.New()
	tok.Set(jwt.IssuerKey, "test")
	tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour).Unix())

	signed, err := jwt.Sign(tok, jwt.WithKey(alg, key))
	require.NoError(t, err, `jwt.Sign should succeed`)

	// Standard parse should work (fast path)
	t.Run("strict parse succeeds", func(t *testing.T) {
		t.Parallel()
		_, err := jwt.Parse(signed, jwt.WithKey(alg, key))
		require.NoError(t, err, `jwt.Parse should succeed with strict base64`)
	})

	// WithStrictBase64Encoding(false) should fall through to the standard path
	// and still succeed with normally-encoded tokens.
	t.Run("lenient parse succeeds with standard encoding", func(t *testing.T) {
		t.Parallel()
		parsed, err := jwt.Parse(signed, jwt.WithKey(alg, key), jwt.WithStrictBase64Encoding(false))
		require.NoError(t, err, `jwt.Parse should succeed with lenient mode on standard input`)
		iss, ok := parsed.Issuer()
		require.True(t, ok, `issuer should be present`)
		require.Equal(t, "test", iss, `issuer claim should match`)
	})

	// WithStrictBase64Encoding(true) should be equivalent to the default
	t.Run("explicit strict parse succeeds", func(t *testing.T) {
		t.Parallel()
		parsed, err := jwt.Parse(signed, jwt.WithKey(alg, key), jwt.WithStrictBase64Encoding(true))
		require.NoError(t, err, `jwt.Parse should succeed with explicit strict mode`)
		iss, ok := parsed.Issuer()
		require.True(t, ok, `issuer should be present`)
		require.Equal(t, "test", iss, `issuer claim should match`)
	})

	// Build a compact JWS with padded base64url payload (non-standard but seen in the wild).
	parts := strings.SplitN(string(signed), ".", 3)
	require.Len(t, parts, 3, `signed JWT should have 3 parts`)

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err, `base64 decode should succeed`)
	paddedPayload := base64.URLEncoding.EncodeToString(payloadBytes)

	// Keep original header (unpadded), re-compute HMAC over padded signing input
	signingInput := parts[0] + "." + paddedPayload
	hmacSig := computeHMAC(t, []byte(signingInput), key)
	paddedCompact := []byte(signingInput + "." + base64.RawURLEncoding.EncodeToString(hmacSig))

	// When verification is on, the fast path uses strict base64 (DecodeStrict)
	// which rejects padded encoding.
	t.Run("padded payload fails with verify", func(t *testing.T) {
		t.Parallel()
		_, err := jwt.Parse(paddedCompact, jwt.WithKey(alg, key))
		require.Error(t, err, `jwt.Parse should fail: padded payload not decodable with strict base64`)
		// The error should point the caller at the escape hatch.
		require.Contains(t, err.Error(), `WithStrictBase64Encoding(false)`,
			`error should name the option that flips to lenient base64`)
	})

	// Lenient mode with no verification: auto-detection handles padded base64.
	t.Run("padded payload succeeds lenient no-verify", func(t *testing.T) {
		t.Parallel()
		parsed, err := jwt.Parse(paddedCompact, jwt.WithVerify(false), jwt.WithStrictBase64Encoding(false))
		require.NoError(t, err, `jwt.Parse should succeed with lenient base64 and no verification`)
		iss, ok := parsed.Issuer()
		require.True(t, ok, `issuer should be present`)
		require.Equal(t, "test", iss, `issuer claim should match`)
	})
}

func computeHMAC(t *testing.T, data, key []byte) []byte {
	t.Helper()
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func TestJWTParseVerify(t *testing.T) {
	t.Parallel()

	keys := make([]any, 0, 6)

	keys = append(keys, []byte("abracadabra"))

	rsaPrivKey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err, "RSA key generated")
	keys = append(keys, rsaPrivKey)

	for _, alg := range []jwa.EllipticCurveAlgorithm{jwa.P256(), jwa.P384(), jwa.P521()} {
		ecdsaPrivKey, err := jwxtest.GenerateEcdsaKey(alg)
		require.NoError(t, err, "jwxtest.GenerateEcdsaKey should succeed for %s", alg)
		keys = append(keys, ecdsaPrivKey)
	}

	ed25519PrivKey, err := jwxtest.GenerateEd25519Key()
	require.NoError(t, err, `jwxtest.GenerateEd25519Key should succeed`)
	keys = append(keys, ed25519PrivKey)

	for _, key := range keys {
		t.Run(fmt.Sprintf("Key=%T", key), func(t *testing.T) {
			t.Parallel()
			algs, err := jws.AlgorithmsForKey(key)
			require.NoError(t, err, `jwas.AlgorithmsForKey should succeed`)

			var dummyRawKey any
			switch pk := key.(type) {
			case *rsa.PrivateKey:
				dummyRawKey, err = jwxtest.GenerateRsaKey()
				require.NoError(t, err, `jwxtest.GenerateRsaKey should succeed`)
			case *ecdsa.PrivateKey:
				alg, err := ourecdsa.AlgorithmFromCurve(pk.Curve)
				if err != nil {
					require.Fail(t, `unsupported elliptic.Curve: %w`, alg)
				}
				dummyRawKey, err = jwxtest.GenerateEcdsaKey(alg)
				require.NoError(t, err, `jwxtest.GenerateEcdsaKey should succeed`)
			case ed25519.PrivateKey:
				dummyRawKey, err = jwxtest.GenerateEd25519Key()
				require.NoError(t, err, `jwxtest.GenerateEd25519Key should succeed`)
			case []byte:
				dummyRawKey = jwxtest.GenerateSymmetricKey()
			default:
				require.Fail(t, fmt.Sprintf("Unhandled key type %T", key))
			}

			testcases := []struct {
				SetAlgorithm   bool
				SetKid         bool
				InferAlgorithm bool
				Error          bool
			}{
				{
					SetAlgorithm:   true,
					SetKid:         true,
					InferAlgorithm: true,
				},
				{
					SetAlgorithm:   true,
					SetKid:         true,
					InferAlgorithm: false,
				},
				{
					SetAlgorithm:   true,
					SetKid:         false,
					InferAlgorithm: true,
					Error:          true,
				},
				{
					SetAlgorithm:   false,
					SetKid:         true,
					InferAlgorithm: true,
				},
				{
					SetAlgorithm:   false,
					SetKid:         true,
					InferAlgorithm: false,
					Error:          true,
				},
				{
					SetAlgorithm:   false,
					SetKid:         false,
					InferAlgorithm: true,
					Error:          true,
				},
				{
					SetAlgorithm:   true,
					SetKid:         false,
					InferAlgorithm: false,
					Error:          true,
				},
				{
					SetAlgorithm:   false,
					SetKid:         false,
					InferAlgorithm: false,
					Error:          true,
				},
			}
			for _, alg := range algs {
				for _, tc := range testcases {
					t.Run(fmt.Sprintf("Algorithm=%s, SetAlgorithm=%t, SetKid=%t, InferAlgorithm=%t, Expect Error=%t", alg, tc.SetAlgorithm, tc.SetKid, tc.InferAlgorithm, tc.Error), func(t *testing.T) {
						t.Parallel()

						const kid = "test-jwt-parse-verify-kid"
						const dummyKid = "test-jwt-parse-verify-dummy-kid"
						hdrs := jws.NewHeaders()
						hdrs.Set(jws.KeyIDKey, kid)

						t1 := jwt.New()
						signed, err := jwt.Sign(t1, jwt.WithKey(alg, key, jws.WithProtectedHeaders(hdrs)))
						require.NoError(t, err, "token.Sign should succeed")

						pubkey, err := jwk.PublicKeyOf(key)
						require.NoError(t, err, `jwk.PublicKeyOf should succeed`)

						if tc.SetAlgorithm {
							pubkey.Set(jwk.AlgorithmKey, alg)
						}

						dummyKey, err := jwk.PublicKeyOf(dummyRawKey)
						require.NoError(t, err, `jwk.PublicKeyOf should succeed`)

						if tc.SetKid {
							pubkey.Set(jwk.KeyIDKey, kid)
							dummyKey.Set(jwk.KeyIDKey, dummyKid)
						}

						// Permute on the location of the correct key, to check for possible
						// cases where we loop too little or too much.
						for i := range 6 {
							var name string
							set := jwk.NewSet()
							switch i {
							case 0:
								name = "Lone key"
								set.AddKey(pubkey)
							case 1:
								name = "Two keys, correct one at the end"
								set.AddKey(dummyKey)
								set.AddKey(pubkey)
							case 2:
								name = "Two keys, correct one at the beginning"
								set.AddKey(pubkey)
								set.AddKey(dummyKey)
							case 3:
								name = "Three keys, correct one at the end"
								set.AddKey(dummyKey)
								set.AddKey(dummyKey)
								set.AddKey(pubkey)
							case 4:
								name = "Three keys, correct one at the middle"
								set.AddKey(dummyKey)
								set.AddKey(pubkey)
								set.AddKey(dummyKey)
							case 5:
								name = "Three keys, correct one at the beginning"
								set.AddKey(pubkey)
								set.AddKey(dummyKey)
								set.AddKey(dummyKey)
							}

							t.Run(name, func(t *testing.T) {
								options := []jwt.ParseOption{
									jwt.WithKeySet(set, jws.WithInferAlgorithmFromKey(tc.InferAlgorithm)),
								}
								t2, err := jwt.Parse(signed, options...)

								if tc.Error {
									require.Error(t, err, `jwt.Parse should fail`)
									return
								}

								require.NoError(t, err, `jwt.Parse should succeed`)
								require.True(t, jwt.Equal(t1, t2), `t1 == t2`)
							})
						}
					})
				}
			}
		})
	}
	t.Run("Miscellaneous", func(t *testing.T) {
		key, err := jwxtest.GenerateRsaKey()
		require.NoError(t, err, "RSA key generated")
		var alg = jwa.RS256()
		const kid = "my-very-special-key"
		hdrs := jws.NewHeaders()
		hdrs.Set(jws.KeyIDKey, kid)
		t1 := jwt.New()
		signed, err := jwt.Sign(t1, jwt.WithKey(alg, key, jws.WithProtectedHeaders(hdrs)))
		require.NoError(t, err, "token.Sign should succeed")

		t.Run("Alg does not match", func(t *testing.T) {
			t.Parallel()
			pubkey, err := jwk.PublicKeyOf(key)
			require.NoError(t, err)

			require.NoError(t, pubkey.Set(jwk.AlgorithmKey, jwa.HS256()), `pubkey.Set should succeed`)
			require.NoError(t, pubkey.Set(jwk.KeyIDKey, kid), `pubkey.Set should succeed`)
			set := jwk.NewSet()
			set.AddKey(pubkey)

			_, err = jwt.Parse(signed, jwt.WithKeySet(set, jws.WithInferAlgorithmFromKey(true), jws.WithUseDefault(true)))
			require.Error(t, err, `jwt.Parse should fail`)
		})
		t.Run("UseDefault with a key set with 1 key", func(t *testing.T) {
			t.Parallel()
			pubkey, err := jwk.PublicKeyOf(key)
			require.NoError(t, err)

			pubkey.Set(jwk.AlgorithmKey, alg)
			pubkey.Set(jwk.KeyIDKey, kid)
			signedNoKid, err := jwt.Sign(t1, jwt.WithKey(alg, key))
			if err != nil {
				t.Fatal("Failed to sign JWT")
			}
			set := jwk.NewSet()
			set.AddKey(pubkey)
			t2, err := jwt.Parse(signedNoKid, jwt.WithKeySet(set, jws.WithUseDefault(true)))
			require.NoError(t, err, `jwt.Parse with key set should succeed`)
			require.True(t, jwt.Equal(t1, t2), `t1 == t2`)
		})
		t.Run("UseDefault with multiple keys should fail", func(t *testing.T) {
			t.Parallel()
			pubkey1, err := jwk.Import[jwk.Key](&key.PublicKey)
			require.NoError(t, err)
			pubkey2, err := jwk.Import[jwk.Key](&key.PublicKey)
			require.NoError(t, err)

			pubkey1.Set(jwk.KeyIDKey, kid)
			pubkey2.Set(jwk.KeyIDKey, "test-jwt-parse-verify-kid-2")
			signedNoKid, err := jwt.Sign(t1, jwt.WithKey(alg, key))
			if err != nil {
				t.Fatal("Failed to sign JWT")
			}
			set := jwk.NewSet()
			set.AddKey(pubkey1)
			set.AddKey(pubkey2)
			_, err = jwt.Parse(signedNoKid, jwt.WithKeySet(set, jws.WithUseDefault(true)))
			require.Error(t, err, `jwt.Parse should fail`)
		})
		// This is a test to check if we allow alg: none in the protected header section.
		// But in truth, since we delegate everything to jws.Verify anyways, it's really
		// a test to see if jws.Verify returns an error if alg: none is specified in the
		// header section. Move this test to jws if need be.
		t.Run("Check alg=none", func(t *testing.T) {
			t.Parallel()
			// Create a signed payload, but use alg=none
			_, payload, signature, err := jwsbb.SplitCompact(signed)
			require.NoError(t, err, `jwsbb.SplitCompact should succeed`)

			dummyHeader := jws.NewHeaders()
			for _, k := range hdrs.Keys() {
				v, ok := hdrs.Field(k)
				require.True(t, ok, `hdrs.Field should succeed`)
				require.NoError(t, dummyHeader.Set(k, v), `dummyHeader.Set should succeed`)
			}
			dummyHeader.Set(jws.AlgorithmKey, jwa.NoSignature)

			dummyMarshaled, err := json.Marshal(dummyHeader)
			require.NoError(t, err, `json.Marshal should succeed`)
			dummyEncoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(dummyMarshaled)))
			base64.RawURLEncoding.Encode(dummyEncoded, dummyMarshaled)

			signedButNot := bytes.Join([][]byte{dummyEncoded, payload, signature}, []byte{tokens.Period})

			pubkey, err := jwk.Import[jwk.Key](&key.PublicKey)
			require.NoError(t, err)

			pubkey.Set(jwk.KeyIDKey, kid)

			set := jwk.NewSet()
			set.AddKey(pubkey)
			_, err = jwt.Parse(signedButNot, jwt.WithKeySet(set))
			// This should fail
			require.Error(t, err, `jwt.Parse with key set + alg=none should fail`)
		})
	})
}

func TestValidateClaims(t *testing.T) {
	t.Parallel()
	// GitHub issue #37: tokens are invalid in the second they are created (because Now() is not after IssuedAt())
	t.Run("Empty fields", func(t *testing.T) {
		t.Parallel()
		token := jwt.New()
		require.Error(t, jwt.Validate(token, jwt.WithIssuer("foo")), `token.Validate should fail`)
		require.Error(t, jwt.Validate(token, jwt.WithJwtID("foo")), `token.Validate should fail`)
		require.Error(t, jwt.Validate(token, jwt.WithSubject("foo")), `token.Validate should fail`)
	})
	t.Run("Reset Validator, No validator", func(t *testing.T) {
		t.Parallel()
		token := jwt.New()
		now := time.Now().UTC()
		token.Set(jwt.IssuedAtKey, now)

		err := jwt.Validate(token, jwt.WithResetValidators(true))
		require.Error(t, err, `token.Validate should fail`)
		require.Contains(t, err.Error(), "no validators specified", `error message should contain "no validators specified"`)
	})
	t.Run("Reset Validator, Check iss only", func(t *testing.T) {
		t.Parallel()
		token := jwt.New()
		iat := time.Now().UTC().Add(time.Hour * 24)
		token.Set(jwt.IssuedAtKey, iat)
		token.Set(jwt.IssuerKey, "github.com/lestrrat-go")

		err := jwt.Validate(token, jwt.WithResetValidators(true), jwt.WithIssuer("github.com/lestrrat-go"))
		require.NoError(t, err, `token.Validate should succeed`)
	})
	t.Run(jwt.IssuedAtKey+"+skew", func(t *testing.T) {
		t.Parallel()
		token := jwt.New()
		now := time.Now().UTC()
		token.Set(jwt.IssuedAtKey, now)

		const DefaultSkew = 0

		args := []jwt.ValidateOption{
			jwt.WithClock(jwt.ClockFunc(func() time.Time { return now })),
			jwt.WithAcceptableSkew(DefaultSkew),
		}

		require.NoError(t, jwt.Validate(token, args...), "token.Validate should validate tokens in the same second they are created")
	})
}

const aLongLongTimeAgo = 233431200
const aLongLongTimeAgoString = "233431200"

func TestUnmarshal(t *testing.T) {
	t.Parallel()
	testcases := []struct {
		Title        string
		Source       string
		Expected     func() jwt.Token
		ExpectedJSON string
	}{
		{
			Title:  "single aud",
			Source: `{"aud":"foo"}`,
			Expected: func() jwt.Token {
				t := jwt.New()
				t.Set("aud", "foo")
				return t
			},
			ExpectedJSON: `{"aud":["foo"]}`,
		},
		{
			Title:  "multiple aud's",
			Source: `{"aud":["foo","bar"]}`,
			Expected: func() jwt.Token {
				t := jwt.New()
				t.Set("aud", []string{"foo", "bar"})
				return t
			},
			ExpectedJSON: `{"aud":["foo","bar"]}`,
		},
		{
			Title:  "issuedAt",
			Source: `{"` + jwt.IssuedAtKey + `":` + aLongLongTimeAgoString + `}`,
			Expected: func() jwt.Token {
				t := jwt.New()
				t.Set(jwt.IssuedAtKey, aLongLongTimeAgo)
				return t
			},
			ExpectedJSON: `{"` + jwt.IssuedAtKey + `":` + aLongLongTimeAgoString + `}`,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.Title, func(t *testing.T) {
			t.Parallel()
			token := jwt.New()
			require.NoError(t, json.Unmarshal([]byte(tc.Source), &token), `json.Unmarshal should succeed`)
			require.Equal(t, tc.Expected(), token, `token should match expected value`)

			b, err := json.Marshal(token)
			require.NoError(t, err, `json.Marshal should succeed`)
			require.Equal(t, tc.ExpectedJSON, string(b), `json should match`)
		})
	}
}

func TestGH52(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	t.Parallel()
	priv, err := jwxtest.GenerateEcdsaKey(jwa.P521())
	require.NoError(t, err)

	pub := &priv.PublicKey
	require.NoError(t, err)
	const iterations = 100
	var wg sync.WaitGroup
	wg.Add(iterations)
	for i := range iterations {
		// Do not use t.Run here as it will clutter up the outpuA
		go func(t *testing.T, priv *ecdsa.PrivateKey, i int) {
			defer wg.Done()
			tok := jwt.New()

			s, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), priv))
			require.NoError(t, err)
			_, err = jws.Verify(s, jws.WithKey(jwa.ES256(), pub))
			require.NoError(t, err, `test should pass (run %d)`, i)
		}(t, priv, i)
	}
	wg.Wait()
}

func TestUnmarshalJSON(t *testing.T) {
	t.Parallel()
	t.Run("Unmarshal audience with multiple values", func(t *testing.T) {
		t.Parallel()
		t1 := jwt.New()
		require.NoError(t, json.Unmarshal([]byte(`{"aud":["foo", "bar", "baz"]}`), &t1), `jwt.Parse should succeed`)

		aud, ok := t1.Audience()
		require.True(t, ok, `t1.Audience() should succeed`)

		require.Equal(t, aud, []string{"foo", "bar", "baz"}, "audience should match. got %v", aud)
	})
}

func TestSignErrors(t *testing.T) {
	t.Parallel()
	priv, err := jwxtest.GenerateEcdsaKey(jwa.P521())
	require.NoError(t, err, `jwxtest.GenerateEcdsaKey should succeed`)

	tok := jwt.New()
	_, err = jwt.Sign(tok, jwt.WithKey(jwa.NewSignatureAlgorithm("BOGUS"), priv))
	require.Error(t, err)

	require.Contains(t, err.Error(), `dsig algorithm "BOGUS" not registered`)

	_, err = jwt.Sign(tok, jwt.WithKey(jwa.ES256(), nil))
	require.Error(t, err)
}

func TestSignJWK(t *testing.T) {
	t.Parallel()
	priv, err := jwxtest.GenerateRsaKey()
	require.Nil(t, err)

	key, err := jwk.Import[jwk.Key](priv)
	require.Nil(t, err)

	require.NoError(t, key.Set(jwk.KeyIDKey, "test"), `key.Set should succeed`)
	require.NoError(t, key.Set(jwk.AlgorithmKey, jwa.RS256()), `key.Set should succeed`)

	tok := jwt.New()
	alg, ok := key.Algorithm()
	require.True(t, ok, `key.Algorithm should succeed`)
	signed, err := jwt.Sign(tok, jwt.WithKey(alg, key))
	require.Nil(t, err)

	header, err := jws.ParseString(string(signed))
	require.Nil(t, err)

	signatures := header.LookupSignature("test")
	require.Len(t, signatures, 1)
}

func getJWTHeaders(jwt []byte) (jws.Headers, error) {
	msg, err := jws.Parse(jwt)
	if err != nil {
		return nil, err
	}
	return msg.Signatures()[0].ProtectedHeaders(), nil
}

func TestSignTyp(t *testing.T) {
	t.Parallel()
	key, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err)

	t.Run(`"typ" header parameter should be set to JWT by default`, func(t *testing.T) {
		t.Parallel()
		t1 := jwt.New()
		signed, err := jwt.Sign(t1, jwt.WithKey(jwa.RS256(), key))
		require.NoError(t, err)
		got, err := getJWTHeaders(signed)
		require.NoError(t, err)
		v, ok := got.Type()
		require.True(t, ok, `"typ" header parameter should be set`)
		require.Equal(t, `JWT`, v, `"typ" header parameter should be set to JWT`)
	})

	// jwt.Sign has two code paths: a fast path (single WithKey option)
	// that hardcodes headers, and a serializer path (2+ options) that
	// populates headers via setTypeOrCty. Verify both paths produce
	// identical protected headers so any divergence is caught generically.
	t.Run(`fast path and serializer path produce identical headers`, func(t *testing.T) {
		t.Parallel()
		t1 := jwt.New()

		fast, err := jwt.Sign(t1, jwt.WithKey(jwa.RS256(), key))
		require.NoError(t, err)
		fastHdrs, err := getJWTHeaders(fast)
		require.NoError(t, err)

		slow, err := jwt.Sign(t1, jwt.WithKey(jwa.RS256(), key), jwt.WithBase64Encoder(base64.RawURLEncoding))
		require.NoError(t, err)
		slowHdrs, err := getJWTHeaders(slow)
		require.NoError(t, err)

		// Compare every field the fast path sets.
		// If a new auto-populated header is added to the fast path
		// but not the serializer path (or vice versa), this will catch it.
		for _, field := range []string{"alg", "typ"} {
			fv, fok := fastHdrs.Field(field)
			sv, sok := slowHdrs.Field(field)
			require.Equal(t, fok, sok, `presence of %q should match between fast and slow paths`, field)
			require.Equal(t, fv, sv, `value of %q should match between fast and slow paths`, field)
		}
	})

	t.Run(`"typ" header parameter should be customizable by WithHeaders`, func(t *testing.T) {
		t.Parallel()
		t1 := jwt.New()
		hdrs := jws.NewHeaders()
		hdrs.Set(`typ`, `custom-typ`)
		signed, err := jwt.Sign(t1, jwt.WithKey(jwa.RS256(), key, jws.WithProtectedHeaders(hdrs)))
		require.NoError(t, err)
		got, err := getJWTHeaders(signed)
		require.NoError(t, err)
		v, ok := got.Type()
		require.True(t, ok, `"typ" header parameter should be set`)
		require.Equal(t, `custom-typ`, v, `"typ" header parameter should be set to the custom value`)
	})
}

func TestReadFile(t *testing.T) {
	t.Parallel()

	f, err := os.CreateTemp(t.TempDir(), "test-read-file-*.jwt")
	require.NoError(t, err, `os.CreateTemp should succeed`)
	defer f.Close()

	token := jwt.New()
	token.Set(jwt.IssuerKey, `lestrrat`)
	b, err := json.Marshal(token)
	require.NoError(t, err, `json.Marshal should succeed`)
	_, err = f.Write(b)
	require.NoError(t, err, `f.Write should succeed`)
	_, err = jwt.ParseFS(os.DirFS(filepath.Dir(f.Name())), filepath.Base(f.Name()), jwt.WithVerify(false), jwt.WithValidate(true), jwt.WithIssuer("lestrrat"))
	require.NoError(t, err, `jwt.ParseFS should succeed`)
	_, err = jwt.ParseFS(os.DirFS(filepath.Dir(f.Name())), filepath.Base(f.Name()), jwt.WithVerify(false), jwt.WithValidate(true), jwt.WithIssuer("lestrrrrrat"))
	require.Error(t, err, `jwt.ParseFS should fail`)

	// ReadFile accepts the absolute path returned by os.CreateTemp — a case
	// os.DirFS would reject. Exercises the v3 source-compatible entry point.
	_, err = jwt.ReadFile(f.Name(), jwt.WithVerify(false), jwt.WithValidate(true), jwt.WithIssuer("lestrrat"))
	require.NoError(t, err, `jwt.ReadFile should succeed`)
}

func TestCustomField(t *testing.T) {
	// XXX has global effect!!!
	const rfc3339Key = `x-test-rfc3339`
	const rfc1123Key = `x-test-rfc1123`
	jwt.RegisterCustomField[time.Time](rfc3339Key)
	jwt.RegisterCustomDecoder(rfc1123Key, jwt.CustomDecodeFunc[time.Time](func(data []byte) (time.Time, error) {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return time.Time{}, err
		}
		return time.Parse(time.RFC1123, s)
	}))

	defer jwt.UnregisterCustomField(rfc3339Key)
	defer jwt.UnregisterCustomField(rfc1123Key)

	expected := time.Date(2015, 11, 4, 5, 12, 52, 0, time.UTC)

	rfc3339bytes, _ := expected.MarshalText() // RFC3339
	rfc1123bytes := expected.Format(time.RFC1123)
	var b strings.Builder
	b.WriteString(`{"iss": "github.com/lesstrrat-go/jwx", "`)
	b.WriteString(rfc3339Key)
	b.WriteString(`": "`)
	b.Write(rfc3339bytes)
	b.WriteString(`", "`)
	b.WriteString(rfc1123Key)
	b.WriteString(`": "`)
	b.WriteString(rfc1123bytes)
	b.WriteString(`"}`)
	src := b.String()

	t.Run("jwt.Parse", func(t *testing.T) {
		token, err := jwt.ParseInsecure([]byte(src))
		require.NoError(t, err, `jwt.Parse should succeed`)
		for _, key := range []string{rfc3339Key, rfc1123Key} {
			fieldV, ok := token.Field(key)
			require.True(t, ok, `token.Field(%q) should succeed`, key)
			v, ok := fieldV.(time.Time)
			require.True(t, ok, `value should be time.Time`)
			require.Equal(t, expected, v, `values should match`)
		}
	})
	t.Run("json.Unmarshal", func(t *testing.T) {
		token := jwt.New()
		require.NoError(t, json.Unmarshal([]byte(src), token), `json.Unmarshal should succeed`)
		for _, key := range []string{rfc3339Key, rfc1123Key} {
			fieldV, ok := token.Field(key)
			require.True(t, ok, `token.Field(%q) should succeed`, key)
			v, ok := fieldV.(time.Time)
			require.True(t, ok, `value should be time.Time`)
			require.Equal(t, expected, v, `values should match`)
		}
	})
}

func TestParseRequest(t *testing.T) {
	const u = "https://github.com/lestrrat-gow/jwx/jwt"
	const xauth = "X-Authorization"

	privkey, _ := jwxtest.GenerateEcdsaJwk()
	require.NoError(t, privkey.Set(jwk.AlgorithmKey, jwa.ES256()), `privkey.Set should succeed`)
	require.NoError(t, privkey.Set(jwk.KeyIDKey, `my-awesome-key`), `privkey.Set should succeed`)
	pubkey, err := jwk.PublicKeyOf(privkey)
	require.NoError(t, err, `jwk.PublicKeyOf should succeed`)
	require.NoError(t, pubkey.Set(jwk.AlgorithmKey, jwa.ES256()), `pubkey.Set should succeed`)

	tok := jwt.New()
	tok.Set(jwt.IssuerKey, u)
	tok.Set(jwt.IssuedAtKey, time.Now().Round(0))

	signed, _ := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), privkey))

	testcases := []struct {
		Request func() *http.Request
		Parse   func(*http.Request) (jwt.Token, error)
		Name    string
		Error   bool
	}{
		{
			Name: "Token not present (w/ multiple options)",
			Request: func() *http.Request {
				return httptest.NewRequestWithContext(t.Context(), http.MethodGet, u, nil)
			},
			Parse: func(req *http.Request) (jwt.Token, error) {
				return jwt.ParseRequest(req,
					jwt.WithHeaderKey("Authorization"),
					jwt.WithHeaderKey(xauth),
					jwt.WithFormKey("access_token"),
					jwt.WithFormKey("token"),
					jwt.WithCookieKey("cookie"),
					jwt.WithKey(jwa.ES256(), pubkey))
			},
			Error: true,
		},
		{
			Name: "Token not present (w/o options)",
			Request: func() *http.Request {
				return httptest.NewRequestWithContext(t.Context(), http.MethodGet, u, nil)
			},
			Parse: func(req *http.Request) (jwt.Token, error) {
				return jwt.ParseRequest(req, jwt.WithKey(jwa.ES256(), pubkey))
			},
			Error: true,
		},
		{
			Name: "Token in Authorization header (w/o extra options)",
			Request: func() *http.Request {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, u, nil)
				req.Header.Add("Authorization", "Bearer "+string(signed))
				return req
			},
			Parse: func(req *http.Request) (jwt.Token, error) {
				return jwt.ParseRequest(req, jwt.WithKey(jwa.ES256(), pubkey))
			},
		},
		{
			Name: "Authorization header: Bearer scheme is case-insensitive (lowercase)",
			Request: func() *http.Request {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, u, nil)
				req.Header.Add("Authorization", "bearer "+string(signed))
				return req
			},
			Parse: func(req *http.Request) (jwt.Token, error) {
				return jwt.ParseRequest(req, jwt.WithKey(jwa.ES256(), pubkey))
			},
		},
		{
			Name: "Authorization header: Bearer scheme is case-insensitive (uppercase)",
			Request: func() *http.Request {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, u, nil)
				req.Header.Add("Authorization", "BEARER "+string(signed))
				return req
			},
			Parse: func(req *http.Request) (jwt.Token, error) {
				return jwt.ParseRequest(req, jwt.WithKey(jwa.ES256(), pubkey))
			},
		},
		{
			Name: "Authorization header: Bearer scheme is case-insensitive (mixed case)",
			Request: func() *http.Request {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, u, nil)
				req.Header.Add("Authorization", "BeArEr "+string(signed))
				return req
			},
			Parse: func(req *http.Request) (jwt.Token, error) {
				return jwt.ParseRequest(req, jwt.WithKey(jwa.ES256(), pubkey))
			},
		},
		{
			Name: "Authorization header: Bearer with tab separator",
			Request: func() *http.Request {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, u, nil)
				req.Header.Add("Authorization", "Bearer\t"+string(signed))
				return req
			},
			Parse: func(req *http.Request) (jwt.Token, error) {
				return jwt.ParseRequest(req, jwt.WithKey(jwa.ES256(), pubkey))
			},
		},
		{
			Name: "Authorization header: Bearer with multiple spaces",
			Request: func() *http.Request {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, u, nil)
				req.Header.Add("Authorization", "Bearer  "+string(signed))
				return req
			},
			Parse: func(req *http.Request) (jwt.Token, error) {
				return jwt.ParseRequest(req, jwt.WithKey(jwa.ES256(), pubkey))
			},
		},
		{
			// Regression: RFC 6750 ABNF requires 1*SP between scheme and
			// credentials. Old code stripped "Bearer" without a separator and
			// silently accepted concatenated forms like "Bearer<token>".
			Name: "Authorization header: Bearer without separator is rejected",
			Request: func() *http.Request {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, u, nil)
				req.Header.Add("Authorization", "Bearer"+string(signed))
				return req
			},
			Parse: func(req *http.Request) (jwt.Token, error) {
				return jwt.ParseRequest(req, jwt.WithKey(jwa.ES256(), pubkey))
			},
			Error: true,
		},
		{
			Name: "Authorization header: non-Bearer scheme is rejected",
			Request: func() *http.Request {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, u, nil)
				req.Header.Add("Authorization", "Basic "+string(signed))
				return req
			},
			Parse: func(req *http.Request) (jwt.Token, error) {
				return jwt.ParseRequest(req, jwt.WithKey(jwa.ES256(), pubkey))
			},
			Error: true,
		},
		{
			Name: "Token in Authorization header (w/o extra options, using jwk.Set)",
			Request: func() *http.Request {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, u, nil)
				req.Header.Add("Authorization", "Bearer "+string(signed))
				return req
			},
			Parse: func(req *http.Request) (jwt.Token, error) {
				set := jwk.NewSet()
				require.NoError(t, set.AddKey(pubkey), `set.AddKey should succeed`)
				return jwt.ParseRequest(req, jwt.WithKeySet(set))
			},
		},
		{
			Name: "Token in Authorization header but we specified another header key",
			Request: func() *http.Request {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, u, nil)
				req.Header.Add("Authorization", "Bearer "+string(signed))
				return req
			},
			Parse: func(req *http.Request) (jwt.Token, error) {
				return jwt.ParseRequest(req, jwt.WithHeaderKey(xauth), jwt.WithKey(jwa.ES256(), pubkey))
			},
			Error: true,
		},
		{
			Name: fmt.Sprintf("Token in %s header (w/ option)", xauth),
			Request: func() *http.Request {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, u, nil)
				req.Header.Add(xauth, string(signed))
				return req
			},
			Parse: func(req *http.Request) (jwt.Token, error) {
				return jwt.ParseRequest(req, jwt.WithHeaderKey(xauth), jwt.WithKey(jwa.ES256(), pubkey))
			},
		},
		{
			Name: fmt.Sprintf("Invalid token in %s header", xauth),
			Request: func() *http.Request {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, u, nil)
				req.Header.Add(xauth, string(signed)+"foobarbaz")
				return req
			},
			Parse: func(req *http.Request) (jwt.Token, error) {
				return jwt.ParseRequest(req, jwt.WithHeaderKey(xauth), jwt.WithKey(jwa.ES256(), pubkey))
			},
			Error: true,
		},
		{
			Name: "Token in access_token form field (w/ option)",
			Request: func() *http.Request {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, u, nil)
				// for whatever reason, I can't populate req.Body and get this to work
				// so populating req.Form directly instead
				req.Form = url.Values{}
				req.Form.Add("access_token", string(signed))
				return req
			},
			Parse: func(req *http.Request) (jwt.Token, error) {
				return jwt.ParseRequest(req, jwt.WithFormKey("access_token"), jwt.WithKey(jwa.ES256(), pubkey))
			},
		},
		{
			Name: "Token in cookie (w/ option)",
			Request: func() *http.Request {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, u, nil)
				req.AddCookie(&http.Cookie{Name: "cookie", Value: string(signed)})
				return req
			},
			Parse: func(req *http.Request) (jwt.Token, error) {
				return jwt.ParseRequest(req, jwt.WithCookieKey("cookie"), jwt.WithKey(jwa.ES256(), pubkey))
			},
		},
		{
			Name: "Invalid token in cookie",
			Request: func() *http.Request {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, u, nil)
				req.AddCookie(&http.Cookie{Name: "cookie", Value: string(signed) + "foobarbaz"})
				return req
			},
			Parse: func(req *http.Request) (jwt.Token, error) {
				return jwt.ParseRequest(req, jwt.WithCookieKey("cookie"), jwt.WithKey(jwa.ES256(), pubkey))
			},
			Error: true,
		},
		{
			Name: "Token in access_token form field (w/o option)",
			Request: func() *http.Request {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, u, nil)
				// for whatever reason, I can't populate req.Body and get this to work
				// so populating req.Form directly instead
				req.Form = url.Values{}
				req.Form.Add("access_token", string(signed))
				return req
			},
			Parse: func(req *http.Request) (jwt.Token, error) {
				return jwt.ParseRequest(req, jwt.WithKey(jwa.ES256(), pubkey))
			},
			Error: true,
		},
		{
			Name: "Invalid token in access_token form field",
			Request: func() *http.Request {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, u, nil)
				// for whatever reason, I can't populate req.Body and get this to work
				// so populating req.Form directly instead
				req.Form = url.Values{}
				req.Form.Add("access_token", string(signed)+"foobarbarz")
				return req
			},
			Parse: func(req *http.Request) (jwt.Token, error) {
				return jwt.ParseRequest(req, jwt.WithKey(jwa.ES256(), pubkey), jwt.WithFormKey("access_token"))
			},
			Error: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.Name, func(t *testing.T) {
			got, err := tc.Parse(tc.Request())
			if tc.Error {
				t.Logf("%s", err)
				require.Error(t, err, `tc.Parse should fail`)
				return
			}

			require.NoError(t, err, `tc.Parse should succeed`)
			require.True(t, jwt.Equal(tok, got), `tokens should match`)
		})
	}

	// One extra test. Make sure we can extract the cookie object that we used
	// when parsing from cookies
	t.Run("jwt.WithCookie", func(t *testing.T) {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, u, nil)
		req.AddCookie(&http.Cookie{Name: "cookie", Value: string(signed)})
		var dst *http.Cookie
		_, err := jwt.ParseRequest(req, jwt.WithCookieKey("cookie"), jwt.WithCookie(&dst), jwt.WithKey(jwa.ES256(), pubkey))
		require.NoError(t, err, `jwt.ParseRequest should succeed`)
		require.NotNil(t, dst, `cookie should be extracted`)
	})

	// Regression: cookie-branch used to drop every error except http.ErrNoCookie,
	// so an expired/invalid JWT in the cookie was reported as "missing cookie".
	t.Run("cookie with expired token surfaces real error", func(t *testing.T) {
		expiredTok := jwt.New()
		require.NoError(t, expiredTok.Set(jwt.IssuerKey, u))
		require.NoError(t, expiredTok.Set(jwt.ExpirationKey, time.Now().Add(-time.Hour)))
		expiredSigned, err := jwt.Sign(expiredTok, jwt.WithKey(jwa.ES256(), privkey))
		require.NoError(t, err, `jwt.Sign should succeed`)

		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, u, nil)
		req.AddCookie(&http.Cookie{Name: "cookie", Value: string(expiredSigned)})

		_, err = jwt.ParseRequest(req, jwt.WithCookieKey("cookie"), jwt.WithKey(jwa.ES256(), pubkey))
		require.Error(t, err, `jwt.ParseRequest should fail`)
		require.ErrorIs(t, err, jwt.TokenExpiredError{}, `error should report token expiration, not missing cookie`)
		require.NotErrorIs(t, err, http.ErrNoCookie, `error must not masquerade as missing cookie`)
	})

	t.Run("Key names containing %-verbs do not corrupt the error", func(t *testing.T) {
		// Regression test: ParseRequest used to build a dynamic format
		// string (b.String() + "%w" placeholders) fed to fmt.Errorf.
		// strconv.Quote escapes control bytes but not '%', so a header
		// key such as "X-With-%s-Verb" would turn into a format verb
		// and mangle the output with "%!s(MISSING)".
		privkey, _ := jwxtest.GenerateEcdsaJwk()
		require.NoError(t, privkey.Set(jwk.AlgorithmKey, jwa.ES256()))
		pub, err := jwk.PublicKeyOf(privkey)
		require.NoError(t, err)

		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, u, nil)
		req.Header.Set("X-With-%s-Verb", "not-a-jwt")
		_, err = jwt.ParseRequest(req,
			jwt.WithHeaderKey("X-With-%s-Verb"),
			jwt.WithKey(jwa.ES256(), pub))
		require.Error(t, err)
		require.NotContains(t, err.Error(), `%!s(MISSING)`,
			`error must not run percent verbs from caller-supplied keys`)
		require.NotContains(t, err.Error(), `%!(EXTRA `,
			`error must not carry an extra-args banner`)
		require.Contains(t, err.Error(), `X-With-%s-Verb`,
			`error should still include the offending header key verbatim`)
	})

	// Regression: ParseRequest used to call req.ParseForm() whenever the
	// request had a non-zero ContentLength, even when the caller never
	// passed WithFormKey. The bug is reachable when the header/cookie
	// lookup falls through without returning a token: ParseRequest then
	// tries the form path, but with no form keys the call is pure waste.
	// The body must only be touched when at least one WithFormKey was
	// supplied.
	//
	// JSON-body case: stdlib ParseForm bails on non-form Content-Types
	// without reading the body, so the body survives either way; what
	// we can observe is that req.Form is left nil because the guarded
	// code path never runs ParseForm at all.
	t.Run("ParseForm is not called when no WithFormKey is supplied (json body)", func(t *testing.T) {
		body := `{"hello":"world"}`
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, u, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		// No Authorization header on purpose: forces ParseRequest past
		// the header path so the form-handling code is reached.

		_, err := jwt.ParseRequest(req, jwt.WithKey(jwa.ES256(), pubkey))
		require.Error(t, err, `jwt.ParseRequest should fail (no token in request)`)

		require.Nil(t, req.Form, `req.Form must remain nil when no WithFormKey is supplied`)

		got, err := io.ReadAll(req.Body)
		require.NoError(t, err, `req.Body should still be readable after ParseRequest`)
		require.Equal(t, body, string(got), `req.Body must be intact`)
	})

	// Companion case: form-encoded body. stdlib ParseForm DOES drain
	// the body on form Content-Types, so without the guard the handler
	// downstream of ParseRequest would see an empty body.
	t.Run("body is not consumed when no WithFormKey is supplied (form body)", func(t *testing.T) {
		body := `payload=hello&other=world`
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, u, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		// No Authorization header: see note above.

		_, err := jwt.ParseRequest(req, jwt.WithKey(jwa.ES256(), pubkey))
		require.Error(t, err, `jwt.ParseRequest should fail (no token in request)`)

		got, err := io.ReadAll(req.Body)
		require.NoError(t, err, `req.Body should still be readable after ParseRequest`)
		require.Equal(t, body, string(got), `req.Body must be intact when no WithFormKey is supplied`)
	})

	// Regression: ParseRequest used to gate ParseForm on
	// `req.ContentLength > 0`, which silently skipped chunked-transfer
	// requests (ContentLength == -1) and zero-length requests. RFC 6750
	// §2.2 allows form-borne bearer tokens, including under chunked
	// encoding. The guard belongs only on `len(formkeys) > 0` (the
	// caller opted in to body parsing); ContentLength shouldn't gate
	// it. Verifies a token in a chunked POST is found.
	t.Run("token in chunked-transfer form body is found", func(t *testing.T) {
		body := `access_token=` + string(signed)
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, u, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		// Force chunked transfer: clear ContentLength and add the
		// transfer encoding. This mirrors a streaming client that
		// doesn't know the body size in advance.
		req.ContentLength = -1
		req.TransferEncoding = []string{"chunked"}

		got, err := jwt.ParseRequest(req,
			jwt.WithFormKey("access_token"),
			jwt.WithKey(jwa.ES256(), pubkey))
		require.NoError(t, err, `jwt.ParseRequest must accept chunked-transfer form bodies (RFC 6750 §2.2)`)
		require.NotNil(t, got)
	})
}

func TestGHIssue368(t *testing.T) {
	// DO NOT RUN THIS IN PARALLEL
	t.Run("Per-object control of flatten audience", func(t *testing.T) {
		for _, globalFlatten := range []bool{true, false} {
			for _, perObjectFlatten := range []bool{true, false} {
				// per-object settings always wins
				t.Run(fmt.Sprintf("Global=%t, Per-Object=%t", globalFlatten, perObjectFlatten), func(t *testing.T) {
					defer jwt.Settings(jwt.WithFlattenAudience(false))
					jwt.Settings(jwt.WithFlattenAudience(globalFlatten))

					tok, _ := jwt.NewBuilder().
						Audience([]string{"hello"}).
						Build()

					if perObjectFlatten {
						tok.Options().Enable(jwt.FlattenAudience)
					} else {
						tok.Options().Disable(jwt.FlattenAudience)
					}
					buf, err := json.MarshalIndent(tok, "", "  ")
					require.NoError(t, err, `json.MarshalIndent should succeed`)
					var expected string
					if perObjectFlatten {
						expected = `{
  "aud": "hello"
}`
					} else {
						expected = `{
  "aud": [
    "hello"
  ]
}`
					}

					require.Equal(t, expected, string(buf), `output should match`)
				})
			}
		}
	})

	for _, flatten := range []bool{true, false} {
		t.Run(fmt.Sprintf("Test serialization (WithFlattenAudience(%t))", flatten), func(t *testing.T) {
			jwt.Settings(jwt.WithFlattenAudience(flatten))

			t.Run("Single Key", func(t *testing.T) {
				tok := jwt.New()
				_ = tok.Set(jwt.AudienceKey, "hello")

				buf, err := json.MarshalIndent(tok, "", "  ")
				require.NoError(t, err, `json.MarshalIndent should succeed`)

				var expected string
				if flatten {
					expected = `{
  "aud": "hello"
}`
				} else {
					expected = `{
  "aud": [
    "hello"
  ]
}`
				}

				require.Equal(t, expected, string(buf), `output should match`)
			})
			t.Run("Multiple Keys", func(t *testing.T) {
				tok, err := jwt.NewBuilder().
					Audience([]string{"hello", "world"}).
					Build()
				require.NoError(t, err, `jwt.Builder should succeed`)

				buf, err := json.MarshalIndent(tok, "", "  ")
				require.NoError(t, err, `json.MarshalIndent should succeed`)

				const expected = `{
  "aud": [
    "hello",
    "world"
  ]
}`

				require.Equal(t, expected, string(buf), `output should match`)
			})
		})
	}
}

func TestGH375(t *testing.T) {
	key, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err, `jwxtest.GenerateRsaJwk should succeed`)
	key.Set(jwk.KeyIDKey, `test`)

	token, err := jwt.NewBuilder().
		Issuer(`foobar`).
		Build()
	require.NoError(t, err, `jwt.Builder should succeed`)

	signAlg := jwa.RS512()
	signed, err := jwt.Sign(token, jwt.WithKey(signAlg, key))
	require.NoError(t, err, `jwt.Sign should succeed`)

	verifyKey, err := jwk.PublicKeyOf(key)
	require.NoError(t, err, `jwk.PublicKeyOf should succeed`)

	verifyKey.Set(jwk.KeyIDKey, `test`)
	verifyKey.Set(jwk.AlgorithmKey, jwa.RS256) // != jwa.RS512

	ks := jwk.NewSet()
	ks.AddKey(verifyKey)

	_, err = jwt.Parse(signed, jwt.WithKeySet(ks))
	require.Error(t, err, `jwt.Parse should fail`)
}

type Claim struct {
	Foo string
	Bar int64
}

func TestJWTParseWithTypedClaim(t *testing.T) {
	testcases := []struct {
		Name        string
		Options     []jwt.ParseOption
		PostProcess func(*testing.T, any) (*Claim, error)
	}{
		{
			Name:    "Basic",
			Options: []jwt.ParseOption{jwt.WithTypedClaim("typed-claim", Claim{})},
			PostProcess: func(t *testing.T, claim any) (*Claim, error) {
				t.Helper()
				v, ok := claim.(Claim)
				if !ok {
					return nil, fmt.Errorf(`claim value should be of type "Claim", but got %T`, claim)
				}
				return &v, nil
			},
		},
		{
			Name:    "json.RawMessage",
			Options: []jwt.ParseOption{jwt.WithTypedClaim("typed-claim", json.RawMessage{})},
			PostProcess: func(t *testing.T, claim any) (*Claim, error) {
				t.Helper()
				v, ok := claim.(json.RawMessage)
				if !ok {
					return nil, fmt.Errorf(`claim value should be of type "json.RawMessage", but got %T`, claim)
				}

				var c Claim
				if err := json.Unmarshal(v, &c); err != nil {
					return nil, fmt.Errorf(`json.Unmarshal failed: %w`, err)
				}

				return &c, nil
			},
		},
	}

	expected := &Claim{Foo: "Foo", Bar: 0xdeadbeef}
	key, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err, `jwxtest.GenerateRsaKey should succeed`)

	var signed []byte
	{
		token := jwt.New()
		require.NoError(t, token.Set("typed-claim", expected), `expected.Set should succeed`)
		v, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), key))
		require.NoError(t, err, `jwt.Sign should succeed`)
		signed = v
	}

	for _, tc := range testcases {
		t.Run(tc.Name, func(t *testing.T) {
			options := append(tc.Options, jwt.WithVerify(false))
			got, err := jwt.Parse(signed, options...)
			require.NoError(t, err, `jwt.Parse should succeed`)

			v, ok := got.Field("typed-claim")
			require.True(t, ok, `got.Field() should succeed`)

			claim, err := tc.PostProcess(t, v)
			require.NoError(t, err, `tc.PostProcess should succeed`)
			require.Equal(t, claim, expected, `claim should match expected value`)
		})
	}
}

func TestGH393(t *testing.T) {
	t.Run("Non-existent required claims", func(t *testing.T) {
		tok := jwt.New()
		require.Error(t, jwt.Validate(tok, jwt.WithRequiredClaim(jwt.IssuedAtKey)), `jwt.Validate should fail`)
	})
	t.Run("exp - iat < WithMaxDelta(10 secs)", func(t *testing.T) {
		now := time.Now()
		tok, err := jwt.NewBuilder().
			IssuedAt(now).
			Expiration(now.Add(5 * time.Second)).
			Build()
		require.NoError(t, err, `jwt.Builder should succeed`)
		require.Error(t, jwt.Validate(tok, jwt.WithMaxDelta(2*time.Second, jwt.ExpirationKey, jwt.IssuedAtKey)), `jwt.Validate should fail`)
		require.NoError(t, jwt.Validate(tok, jwt.WithMaxDelta(10*time.Second, jwt.ExpirationKey, jwt.IssuedAtKey)), `jwt.Validate should succeed`)
	})
	t.Run("iat - exp (5 secs) < WithMinDelta(10 secs)", func(t *testing.T) {
		now := time.Now()
		tok, err := jwt.NewBuilder().
			IssuedAt(now).
			Expiration(now.Add(5 * time.Second)).
			Build()
		require.NoError(t, err, `jwt.Builder should succeed`)
		require.Error(t, jwt.Validate(tok, jwt.WithMinDelta(10*time.Second, jwt.ExpirationKey, jwt.IssuedAtKey)), `jwt.Validate should fail`)
	})
	t.Run("iat - exp (5 secs) > WithMinDelta(10 secs)", func(t *testing.T) {
		now := time.Now()
		tok, err := jwt.NewBuilder().
			IssuedAt(now).
			Expiration(now.Add(5 * time.Second)).
			Build()
		require.NoError(t, err, `jwt.Builder should succeed`)
		require.NoError(t, jwt.Validate(tok, jwt.WithMinDelta(10*time.Second, jwt.ExpirationKey, jwt.IssuedAtKey), jwt.WithAcceptableSkew(5*time.Second)), `jwt.Validate should succeed`)
	})
	t.Run("now - iat < WithMaxDelta(10 secs)", func(t *testing.T) {
		now := time.Now()
		tok, err := jwt.NewBuilder().
			IssuedAt(now).
			Build()
		require.NoError(t, err, `jwt.Builder should succeed`)
		require.NoError(t, jwt.Validate(tok, jwt.WithMaxDelta(10*time.Second, "", jwt.IssuedAtKey), jwt.WithClock(jwt.ClockFunc(func() time.Time { return now.Add(5 * time.Second) }))), `jwt.Validate should succeed`)
	})
	t.Run("invalid claim name (c1)", func(t *testing.T) {
		now := time.Now()
		tok, err := jwt.NewBuilder().
			Claim("foo", now).
			Expiration(now.Add(5 * time.Second)).
			Build()
		require.NoError(t, err, `jwt.Builder should succeed`)
		require.Error(t, jwt.Validate(tok, jwt.WithMinDelta(10*time.Second, jwt.ExpirationKey, "foo"), jwt.WithAcceptableSkew(5*time.Second)), `jwt.Validate should fail`)
	})
	t.Run("invalid claim name (c2)", func(t *testing.T) {
		now := time.Now()
		tok, err := jwt.NewBuilder().
			Claim("foo", now.Add(5*time.Second)).
			IssuedAt(now).
			Build()
		require.NoError(t, err, `jwt.Builder should succeed`)
		require.Error(t, jwt.Validate(tok, jwt.WithMinDelta(10*time.Second, "foo", jwt.IssuedAtKey), jwt.WithAcceptableSkew(5*time.Second)), `jwt.Validate should fail`)
	})

	// Following tests deviate a little from the original issue, but
	// since they were added for the same issue, we just bundle the
	// tests together
	t.Run(`WithRequiredClaim fails for non-existent claim`, func(t *testing.T) {
		tok := jwt.New()
		require.Error(t, jwt.Validate(tok, jwt.WithRequiredClaim("foo")), `jwt.Validate should fail`)
	})
	t.Run(`WithRequiredClaim succeeds for existing claim`, func(t *testing.T) {
		tok, err := jwt.NewBuilder().
			Claim(`foo`, 1).
			Build()
		require.NoError(t, err, `jwt.Builder should succeed`)
		require.NoError(t, jwt.Validate(tok, jwt.WithRequiredClaim("foo")), `jwt.Validate should fail`)
	})
}

func TestGH430(t *testing.T) {
	t1 := jwt.New()
	err := t1.Set("payload", map[string]any{
		"name": "someone",
	})
	require.NoError(t, err, `t1.Set should succeed`)

	key := []byte("secret")
	signed, err := jwt.Sign(t1, jwt.WithKey(jwa.HS256(), key))
	require.NoError(t, err, `jwt.Sign should succeed`)

	_, err = jwt.Parse(signed, jwt.WithKey(jwa.HS256(), key))
	require.NoError(t, err, `jwt.Parse should succeed`)
}

func TestGH706(t *testing.T) {
	err := jwt.Validate(jwt.New(), jwt.WithRequiredClaim("foo"))
	require.ErrorIs(t, err, jwt.ValidationError{}, `error should be a validation error`)
	require.ErrorIs(t, err, jwt.MissingRequiredClaimError{}, `err should be jwt.ErrRequiredClaim`)
	require.ErrorIs(t, err, &jwt.MissingRequiredClaimError{}, `err should be jwt.ErrRequiredClaim`)

	requiredClaimErr, ok := errors.AsType[jwt.MissingRequiredClaimError](err)
	require.True(t, ok, `errors.AsType should find MissingRequiredClaimError`)
	require.Equal(t, "foo", requiredClaimErr.Claim, `Claim should identify the missing required claim`)
}

func TestBenHigginsByPassRegression(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	// Test if an access token JSON payload parses when provided directly
	//
	// The JSON below is slightly modified example payload from:
	// https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-access-token.html

	// Case 1: add "aud", and adjust exp to be valid
	// Case 2: do not add "aud", adjust exp

	exp := strconv.Itoa(int(time.Now().Unix()) + 1000)
	const tmpl = `{%s
    "sub": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "device_key": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "cognito:groups": ["admin"],
    "token_use": "access",
    "scope": "aws.cognito.signin.user.admin",
    "auth_time": 1562190524,
    "iss": "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_example",
    "exp": %s,
    "iat": 1562190524,
    "origin_jti": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "jti": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "client_id": "57cbishk4j24pabc1234567890",
    "username": "janedoe@example.com"
  }`

	testcases := [][]byte{
		fmt.Appendf(nil, tmpl, `"aud": ["test"],`, exp),
		fmt.Appendf(nil, tmpl, ``, exp),
	}

	for _, tc := range testcases {
		for _, pedantic := range []bool{true, false} {
			_, err = jwt.Parse(
				tc,
				jwt.WithValidate(true),
				jwt.WithPedantic(pedantic),
				jwt.WithKey(jwa.RS256(), &key.PublicKey),
			)
			t.Logf("%s", err)
			require.Error(t, err, `jwt.Parse should fail`)
		}
	}
}

func TestVerifyAuto(t *testing.T) {
	key, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err, `jwxtest.GenerateRsaJwk should succeed`)

	key.Set(jwk.KeyIDKey, `my-awesome-key`)

	pubkey, err := jwk.PublicKeyOf(key)
	require.NoError(t, err, `jwk.PublicKeyOf should succeed`)
	set := jwk.NewSet()
	set.AddKey(pubkey)
	backoffCount := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get(`type`) {
		case "backoff":
			backoffCount++
			if backoffCount == 1 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		json.MarshalEncode(json.NewEncoder(w), set)
	}))
	defer srv.Close()

	tok, err := jwt.NewBuilder().
		Claim(jwt.IssuerKey, `https://github.com/lestrrat-go/jwx/v4`).
		Claim(jwt.SubjectKey, `jku-test`).
		Build()

	require.NoError(t, err, `jwt.NewBuilder.Build() should succeed`)

	hdrs := jws.NewHeaders()
	hdrs.Set(jws.JWKSetURLKey, srv.URL)

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), key, jws.WithProtectedHeaders(hdrs)))
	require.NoError(t, err, `jwt.Sign() should succeed`)

	// Explicit restrictive Allow that matches the URL — permits the
	// fetch, which in turn lets jku verification succeed.
	good := &jwxtest.JKUFetcher{
		Client: srv.Client(),
		Allow:  func(u string) bool { return u == srv.URL },
	}

	parsed, err := jwt.Parse(signed, jwt.WithVerifyAuto(good))
	require.NoError(t, err, `jwt.Parse should succeed`)
	require.True(t, jwt.Equal(tok, parsed), `tokens should be equal`)

	// Nil Allow permits every URL — this is the permissive default
	// that matches jwkfetch.Client's default and jwt.Parse should
	// accept it.
	permissive := &jwxtest.JKUFetcher{Client: srv.Client()}
	parsed, err = jwt.Parse(signed, jwt.WithVerifyAuto(permissive))
	require.NoError(t, err, `jwt.Parse with permissive fetcher should succeed`)
	require.True(t, jwt.Equal(tok, parsed), `tokens should be equal`)

	// A nil fetcher is not permitted — WithVerifyAuto errors at jku
	// verification time rather than silently falling back.
	_, err = jwt.Parse(signed, jwt.WithVerifyAuto(nil))
	require.Error(t, err, `jwt.Parse should fail with nil fetcher`)

	// Explicit restrictive Allow that does not match the URL — the
	// fetcher rejects the fetch, and jku verification surfaces the
	// rejection.
	bad := &jwxtest.JKUFetcher{
		Client: srv.Client(),
		Allow: func(u string) bool {
			return u == `https://github.com/lestrrat-go/jwx/v4`
		},
	}
	_, err = jwt.Parse(signed, jwt.WithVerifyAuto(bad))
	require.Error(t, err, `jwt.Parse should fail when URL is not whitelisted`)

	// Cache test case moved to ext/jwkfetch
}

func TestSerializer(t *testing.T) {
	t.Run(`Invalid sign suboption`, func(t *testing.T) {
		_, err := jwt.NewSerializer().
			Sign(jwt.WithKey(jwa.HS256(), []byte("abracadabra"), jwe.WithCompress(jwa.Deflate()))).
			Serialize(jwt.New())
		require.Error(t, err, `Serialize() should fail`)
	})
	t.Run(`Invalid SignatureAglrotihm`, func(t *testing.T) {
		_, err := jwt.NewSerializer().
			Encrypt(jwt.WithKey(jwa.A256KW(), []byte("abracadabra"))).
			Serialize(jwt.New())
		require.Error(t, err, `Serialize() should succeedl`)
	})
	t.Run(`Invalid encrypt suboption`, func(t *testing.T) {
		_, err := jwt.NewSerializer().
			Encrypt(jwt.WithKey(jwa.A256KW(), []byte("abracadabra"), jws.WithPretty(true))).
			Serialize(jwt.New())
		require.Error(t, err, `Serialize() should fail`)
	})
	t.Run(`Invalid KeyEncryptionAglrotihm`, func(t *testing.T) {
		_, err := jwt.NewSerializer().
			Encrypt(jwt.WithKey(jwa.HS256(), []byte("abracadabra"))).
			Serialize(jwt.New())
		require.Error(t, err, `Serialize() should succeedl`)
	})
}

func TestFractional(t *testing.T) {
	t.Run("FormatPrecision", func(t *testing.T) {
		var nd types.NumericDate
		jwt.Settings(jwt.WithNumericDateParsePrecision(int(types.MaxPrecision)))
		s := fmt.Sprintf("%d.100000001", aLongLongTimeAgo)
		_ = nd.Accept(s)
		jwt.Settings(jwt.WithNumericDateParsePrecision(0))
		testcases := []struct {
			Input     types.NumericDate
			Expected  string
			Precision int
		}{
			{
				Input:    nd,
				Expected: fmt.Sprintf(`%d`, aLongLongTimeAgo),
			},
			{
				Input:    types.NumericDate{Time: time.Unix(0, 1).UTC()},
				Expected: "0",
			},
			{
				Input:     types.NumericDate{Time: time.Unix(0, 1).UTC()},
				Precision: 9,
				Expected:  "0.000000001",
			},
			{
				Input:     types.NumericDate{Time: time.Unix(0, 100000000).UTC()},
				Precision: 9,
				Expected:  "0.100000000",
			},
		}

		for i := 1; i <= int(types.MaxPrecision); i++ {
			fractional := (fmt.Sprintf(`%d`, 100000001))[:i]
			testcases = append(testcases, struct {
				Input     types.NumericDate
				Expected  string
				Precision int
			}{
				Input:     nd,
				Precision: i,
				Expected:  fmt.Sprintf(`%d.%s`, aLongLongTimeAgo, fractional),
			})
		}

		for _, tc := range testcases {
			t.Run(fmt.Sprintf("%s (precision=%d)", tc.Input, tc.Precision), func(t *testing.T) {
				jwt.Settings(jwt.WithNumericDateFormatPrecision(tc.Precision))
				require.Equal(t, tc.Expected, tc.Input.String())
			})
		}
		jwt.Settings(jwt.WithNumericDateFormatPrecision(0))
	})
	t.Run("ParsePrecision", func(t *testing.T) {
		const template = `{"iat":"%s"}`

		testcases := []struct {
			Input     string
			Expected  time.Time
			Precision int
		}{
			{
				Input:    "0",
				Expected: time.Unix(0, 0).UTC(),
			},
			{
				Input:    "0.000000001",
				Expected: time.Unix(0, 0).UTC(),
			},
			{
				Input:    fmt.Sprintf("%d.111111111", aLongLongTimeAgo),
				Expected: time.Unix(aLongLongTimeAgo, 0).UTC(),
			},
			{
				// Max precision
				Input:     fmt.Sprintf("%d.100000001", aLongLongTimeAgo),
				Precision: int(types.MaxPrecision),
				Expected:  time.Unix(aLongLongTimeAgo, 100000001).UTC(),
			},
		}

		for i := 1; i < int(types.MaxPrecision); i++ {
			testcases = append(testcases, struct {
				Input     string
				Expected  time.Time
				Precision int
			}{
				Input:     fmt.Sprintf("%d.100000001", aLongLongTimeAgo),
				Precision: i,
				Expected:  time.Unix(aLongLongTimeAgo, 100000000).UTC(),
			})
		}

		for _, tc := range testcases {
			t.Run(fmt.Sprintf("%s (precision=%d)", tc.Input, tc.Precision), func(t *testing.T) {
				jwt.Settings(jwt.WithNumericDateParsePrecision(tc.Precision))
				tok, err := jwt.Parse(
					fmt.Appendf(nil, template, tc.Input),
					jwt.WithVerify(false),
					jwt.WithValidate(false),
				)
				require.NoError(t, err, `jwt.Parse should succeed`)
				v, ok := tok.IssuedAt()
				require.True(t, ok, `iat should be present`)
				require.Equal(t, tc.Expected, v, `iat should match`)
			})
		}
		jwt.Settings(jwt.WithNumericDateParsePrecision(0))
	})
}

// TestSettingsRejectsOutOfRangePrecision documents that out-of-range
// values for WithNumericDate{Parse,Format}Precision (negative or above
// types.MaxPrecision) cause Settings() to return an error rather than
// silently swallowing the value. The previous behavior was to ignore
// out-of-range values and always return nil — a caller mis-typing the
// precision would get no signal, and the global state would silently
// stay at its previous value.
func TestSettingsRejectsOutOfRangePrecision(t *testing.T) {
	t.Run("parse precision above MaxPrecision", func(t *testing.T) {
		err := jwt.Settings(jwt.WithNumericDateParsePrecision(int(types.MaxPrecision) + 1))
		require.Error(t, err, `Settings must reject parse-precision > MaxPrecision`)
	})

	t.Run("parse precision negative", func(t *testing.T) {
		err := jwt.Settings(jwt.WithNumericDateParsePrecision(-1))
		require.Error(t, err, `Settings must reject negative parse-precision`)
	})

	t.Run("format precision above MaxPrecision", func(t *testing.T) {
		err := jwt.Settings(jwt.WithNumericDateFormatPrecision(int(types.MaxPrecision) + 1))
		require.Error(t, err, `Settings must reject format-precision > MaxPrecision`)
	})

	t.Run("format precision negative", func(t *testing.T) {
		err := jwt.Settings(jwt.WithNumericDateFormatPrecision(-1))
		require.Error(t, err, `Settings must reject negative format-precision`)
	})

	t.Run("valid precision still succeeds", func(t *testing.T) {
		require.NoError(t, jwt.Settings(jwt.WithNumericDateParsePrecision(0)))
		require.NoError(t, jwt.Settings(jwt.WithNumericDateParsePrecision(int(types.MaxPrecision))))
	})
}

func TestGH836(t *testing.T) {
	// tests on TokenOptionSet are found elsewhere.

	t1 := jwt.New()
	t1.Options().Enable(jwt.FlattenAudience)

	require.True(t, t1.Options().IsEnabled(jwt.FlattenAudience), `flag should be enabled`)

	t2, err := t1.Clone()
	require.NoError(t, err, `t1.Clone should succeed`)

	require.True(t, t2.Options().IsEnabled(jwt.FlattenAudience), `cloned token should have same settings`)

	t2.Options().Disable(jwt.FlattenAudience)
	require.True(t, t1.Options().IsEnabled(jwt.FlattenAudience), `flag should be enabled (t2.Options should have no effect on t1.Options)`)
}

func TestGH850(t *testing.T) {
	var testToken = `eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNjY2MDkxMzczLCJmb28iOiJiYXIifQ.3GWevx1z2_uCBB9Vj-D0rsT_CMsMeP9GP2rEqGDWpesoG8nHEjAXJOEQV1jOVkkCtTnS18JhcQdb7dW4i-zmqg.trailing-rubbish`

	_, err := jwt.Parse([]byte(testToken), jwt.WithVerify(false))
	require.True(t, errors.Is(err, jwt.UnknownPayloadTypeError()))
}

func TestGH888(t *testing.T) {
	// Use of "none" is insecure, and we just don't allow it by default.
	// In order to allow none, we must tell jwx that we actually want it.
	token, err := jwt.NewBuilder().
		Subject("foo").
		Issuer("bar").
		Build()

	require.NoError(t, err, `jwt.Builder should succeed`)

	// 1) "none" must be triggered by its own option. Can't use jwt.WithKey(jwa.NoSignature, ...)
	t.Run("jwt.Sign(token, jwt.WithKey(jwa.NoSignature)) should fail", func(t *testing.T) {
		_, err := jwt.Sign(token, jwt.WithKey(jwa.NoSignature(), nil))
		require.Error(t, err, `jwt.Sign with jwt.WithKey should fail`)
	})
	t.Run("jwt.Sign(token, jwt.WithInsecureNoSignature())", func(t *testing.T) {
		signed, err := jwt.Sign(token, jwt.WithInsecureNoSignature())
		require.NoError(t, err, `jwt.Sign should succeed`)

		require.Equal(t, `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJiYXIiLCJzdWIiOiJmb28ifQ.`, string(signed))

		_, err = jwt.Parse(signed)
		require.Error(t, err, `jwt.Parse with alg=none should fail`)
	})
}

func TestGH951(t *testing.T) {
	signKey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err, `jwxtest.GenerateRsaKey should succeed`)

	sharedKey := []byte{
		25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133, 74, 82,
	}

	token, err := jwt.NewBuilder().
		Subject(`test-951`).
		Issuer(`jwt.Test951`).
		Build()
	require.NoError(t, err, `jwt.NewBuilder should succeed`)

	// this whole workflow actually works even if the bug in #951 is present.
	// so we shall compare the results with and without the encryption
	// options to see if there is a difference in the length of the
	// cipher text, which is the second from last component in the message
	serialized, err := jwt.NewSerializer().
		Sign(jwt.WithKey(jwa.RS256(), signKey)).
		Encrypt(
			jwt.WithKey(jwa.A128KW(), sharedKey),
			jwt.WithEncryptOption(jwe.WithContentEncryption(jwa.A128GCM())),
			jwt.WithEncryptOption(jwe.WithCompress(jwa.Deflate())),
		).
		Serialize(token)
	require.NoError(t, err, `jwt.NewSerializer()....Serizlie() should succeed`)

	serialized2, err := jwt.NewSerializer().
		Sign(jwt.WithKey(jwa.RS256(), signKey)).
		Encrypt(
			jwt.WithKey(jwa.A128KW(), sharedKey),
		).
		Serialize(token)
	require.NoError(t, err, `jwt.NewSerializer()....Serizlie() should succeed`)

	require.NotEqual(t,
		len(bytes.Split(serialized, []byte{tokens.Period})[3]),
		len(bytes.Split(serialized2, []byte{tokens.Period})[3]),
	)

	decrypted, err := jwe.Decrypt(serialized, jwe.WithKey(jwa.A128KW(), sharedKey))
	require.NoError(t, err, `jwe.Decrypt should succeed`)

	verified, err := jwt.Parse(decrypted, jwt.WithKey(jwa.RS256(), signKey.PublicKey))
	require.NoError(t, err, `jwt.Parse should succeed`)

	require.True(t, jwt.Equal(verified, token), `tokens should be equal`)
}

func TestGH1007(t *testing.T) {
	key, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err, `jwxtest.GenerateRsaJwk should succeed`)

	tok, err := jwt.NewBuilder().
		Claim(`claim1`, `value1`).
		Claim(`claim2`, `value2`).
		Issuer(`github.com/lestrrat-go/jwx`).
		Audience([]string{`users`}).
		Build()
	require.NoError(t, err, `jwt.NewBuilder should succeed`)

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), key))
	require.NoError(t, err, `jwt.Sign should succeed`)

	// The intended usage of ParseInsecure is without any verification
	// material. This worked from the beginning.
	_, err = jwt.ParseInsecure(signed)
	require.NoError(t, err, `jwt.ParseInsecure should succeed`)

	// #1007 originally asked for ParseInsecure to silently accept a stray
	// WithKey. That was reversed: ParseInsecure now rejects key-bearing
	// options outright so that typos like jwt.ParseInsecure(..., jwt.WithKey(...))
	// cannot silently skip verification. Callers who want the key to be
	// honored must use jwt.Parse.
	wrongPubKey, err := jwxtest.GenerateRsaPublicJwk()
	require.NoError(t, err, `jwxtest.GenerateRsaPublicJwk should succeed`)

	_, err = jwt.ParseInsecure(signed, jwt.WithKey(jwa.RS256(), wrongPubKey))
	require.Error(t, err, `jwt.ParseInsecure with jwt.WithKey() should error`)
	require.ErrorContains(t, err, `jwt.ParseInsecure`)
}

func TestParseInsecureRejectsKeyOptions(t *testing.T) {
	key, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err, `jwxtest.GenerateRsaJwk should succeed`)

	tok, err := jwt.NewBuilder().Issuer(`me`).Build()
	require.NoError(t, err, `jwt.NewBuilder should succeed`)

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), key))
	require.NoError(t, err, `jwt.Sign should succeed`)

	wrongKey, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err, `jwxtest.GenerateRsaJwk should succeed`)

	wrongSet := jwk.NewSet()
	require.NoError(t, wrongSet.AddKey(wrongKey), `set.AddKey should succeed`)

	noopProvider := jws.KeyProviderFunc(func(_ context.Context, _ jws.KeySink, _ *jws.Signature, _ *jws.Message) error {
		return nil
	})

	for _, tc := range []struct {
		name string
		opt  jwt.ParseOption
	}{
		{`WithKey`, jwt.WithKey(jwa.RS256(), wrongKey)},
		{`WithKeySet`, jwt.WithKeySet(wrongSet)},
		{`WithKeyProvider`, jwt.WithKeyProvider(noopProvider)},
		{`WithVerifyAuto`, jwt.WithVerifyAuto(nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := jwt.ParseInsecure(signed, tc.opt)
			require.Error(t, err, `jwt.ParseInsecure with jwt.%s() should error`, tc.name)
			require.ErrorContains(t, err, `jwt.ParseInsecure`)
		})
	}
}

func TestParseJSON(t *testing.T) {
	// NOTE: Unlike in v2, there is no setting for CompactOnly
	privKey, err := jwxtest.GenerateRsaJwk()
	require.NoError(t, err, `jwxtest.GenerateRsaJwk should succeed`)

	signedJSON, err := jws.Sign([]byte(`{}`), jws.WithKey(jwa.RS256(), privKey), jws.WithValidateKey(true), jws.WithJSON())
	require.NoError(t, err, `jws.Sign should succeed`)

	// jws.Verify should succeed
	_, err = jws.Verify(signedJSON, jws.WithKey(jwa.RS256(), privKey))
	require.NoError(t, err, `jws.Verify should succeed`)

	// jwt.Parse should fail
	_, err = jwt.Parse(signedJSON, jwt.WithKey(jwa.RS256(), privKey))
	require.Error(t, err, `jwt.Parse should fail`)
}

func TestGH1175(t *testing.T) {
	token, err := jwt.NewBuilder().
		Expiration(time.Now().Add(-1 * time.Hour)).
		Build()
	require.NoError(t, err, `jwt.NewBuilder should succeed`)
	secret := []byte("secret")
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.HS256(), secret))
	require.NoError(t, err, `jwt.Sign should succeed`)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, `http://example.com`, nil)
	req.Header.Set("Authorization", "Bearer "+string(signed))

	_, err = jwt.ParseRequest(req, jwt.WithKey(jwa.HS256(), secret))
	require.Error(t, err, `jwt.ParseRequest should fail`)
	require.ErrorIs(t, err, jwt.TokenExpiredError{}, `jwt.ParseRequest should fail with jwt.ErrTokenExpired`)
}

func TestGH1482(t *testing.T) {
	tok, _ := jwt.NewBuilder().Issuer("github.com/lestrrat-go/jwx").Build()
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256(), []byte("secret")))
	require.NoError(t, err, `jwt.Sign should succeed`)

	var markerValue any
	kp := jws.KeyProviderFunc(func(ctx context.Context, sink jws.KeySink, _ *jws.Signature, _ *jws.Message) error {
		markerValue = ctx.Value("marker")
		key, err := jwk.Import[jwk.Key]([]byte("secret"))
		if err != nil {
			return err
		}
		sink.Key(jwa.HS256(), key)
		return nil
	})

	//nolint:revive
	ctx := context.WithValue(context.Background(), "marker", "value")

	_, err = jwt.Parse(signed, jwt.WithKeyProvider(kp), jwt.WithContext(ctx))
	require.NoError(t, err, `jwt.Parse should succeed`)
	require.NotEmpty(t, markerValue, "context value 'marker' should be present")
}

// TestGH1484 tests that jwt.Parse rejects JSON null for string registered
// claims (iss, sub, jti) when WithStrictStringClaims is enabled.
// By default, null is silently accepted as "" (Go's standard behavior).
// When strict mode is enabled, null causes an error per the RFC
// StringOrURI type definitions.
func TestGH1484(t *testing.T) {
	testcases := []struct {
		Name    string
		Payload string
	}{
		{Name: "null_sub", Payload: `{"sub":null}`},
		{Name: "null_iss", Payload: `{"iss":null}`},
		{Name: "null_jti", Payload: `{"jti":null}`},
	}

	key, err := jwk.Import[jwk.Key]([]byte("abracadabra"))
	require.NoError(t, err, `jwk.Import should succeed`)

	t.Run("default accepts null", func(t *testing.T) {
		for _, tc := range testcases {
			t.Run(tc.Name, func(t *testing.T) {
				signed, err := jws.Sign([]byte(tc.Payload), jws.WithKey(jwa.HS256(), key))
				require.NoError(t, err, `jws.Sign should succeed`)

				_, err = jwt.Parse(signed, jwt.WithKey(jwa.HS256(), key))
				require.NoError(t, err, `jwt.Parse should accept null claim by default`)
			})
		}
	})

	t.Run("strict rejects null", func(t *testing.T) {
		for _, tc := range testcases {
			t.Run(tc.Name, func(t *testing.T) {
				signed, err := jws.Sign([]byte(tc.Payload), jws.WithKey(jwa.HS256(), key))
				require.NoError(t, err, `jws.Sign should succeed`)

				_, err = jwt.Parse(signed, jwt.WithKey(jwa.HS256(), key), jwt.WithStrictStringClaims(true))
				require.Error(t, err, `jwt.Parse should reject null claim when strict`)
			})
		}
	})
}
