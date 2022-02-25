package bench_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/internal/jwxtest"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

func BenchmarkJWT(b *testing.B) {
	alg := jwa.RS256

	key, err := jwxtest.GenerateRsaJwk()
	if err != nil {
		b.Fatal(err)
	}
	pubkey, err := jwk.PublicKeyOf(key)
	if err != nil {
		b.Fatal(err)
	}

	t1 := jwt.New()
	t1.Set(jwt.IssuedAtKey, time.Now().Unix())
	t1.Set(jwt.ExpirationKey, time.Now().Add(time.Hour).Unix())

	b.Run("Serialization", func(b *testing.B) {
		b.Run("Compact", func(b *testing.B) {
			testcases := []Case{
				{
					Name: "jwt.Sign",
					Test: func(b *testing.B) error {
						_, err := jwt.Sign(t1, jwt.WithKey(alg, key))
						return err
					},
				},
			}
			for _, tc := range testcases {
				tc.Run(b)
			}
		})
		b.Run("JSON", func(b *testing.B) {
			testcases := []Case{
				{
					Name: "json.Marshal",
					Test: func(b *testing.B) error {
						_, err := json.Marshal(t1)
						return err
					},
				},
			}
			for _, tc := range testcases {
				tc.Run(b)
			}
		})
	})

	b.Run("Serialization", func(b *testing.B) {
		signedBuf, err := jwt.Sign(t1, jwt.WithKey(alg, key))
		if err != nil {
			b.Fatal(err)
		}

		signedString := string(signedBuf)
		signedReader := bytes.NewReader(signedBuf)
		jsonBuf, _ := json.Marshal(t1)
		jsonString := string(jsonBuf)
		jsonReader := bytes.NewReader(jsonBuf)

		b.Run("Compact (With Verify)", func(b *testing.B) {
			testcases := []Case{
				{
					Name:      "jwt.ParseString",
					SkipShort: true,
					Test: func(b *testing.B) error {
						_, err := jwt.ParseString(signedString, jwt.WithKey(alg, pubkey))
						return err
					},
				},
				{
					Name: "jwt.Parse",
					Test: func(b *testing.B) error {
						_, err := jwt.Parse(signedBuf, jwt.WithKey(alg, pubkey))
						return err
					},
				},
				{
					Name:      "jwt.ParseReader",
					SkipShort: true,
					Pretest: func(b *testing.B) error {
						_, err := signedReader.Seek(0, 0)
						return err
					},
					Test: func(b *testing.B) error {
						_, err := jwt.ParseReader(signedReader, jwt.WithKey(alg, pubkey))
						return err
					},
				},
			}
			for _, tc := range testcases {
				tc.Run(b)
			}
		})
		b.Run("Compact (No Verify)", func(b *testing.B) {
			testcases := []Case{
				{
					Name:      "jwt.ParseString",
					SkipShort: true,
					Test: func(b *testing.B) error {
						_, err := jwt.ParseString(signedString)
						return err
					},
				},
				{
					Name: "jwt.Parse",
					Test: func(b *testing.B) error {
						_, err := jwt.Parse(signedBuf)
						return err
					},
				},
				{
					Name:      "jwt.ParseReader",
					SkipShort: true,
					Pretest: func(b *testing.B) error {
						_, err := signedReader.Seek(0, 0)
						return err
					},
					Test: func(b *testing.B) error {
						_, err := jwt.ParseReader(signedReader)
						return err
					},
				},
			}
			for _, tc := range testcases {
				tc.Run(b)
			}
		})
		b.Run("JSON", func(b *testing.B) {
			var v interface{}
			testcases := []Case{
				{
					Name:      "jwt.ParseString",
					SkipShort: true,
					Test: func(b *testing.B) error {
						_, err := jwt.ParseString(jsonString)
						return err
					},
				},
				{
					Name: "jwt.Parse",
					Test: func(b *testing.B) error {
						_, err := jwt.Parse(jsonBuf)
						return err
					},
				},
				{
					Name:      "jwt.ParseReader",
					SkipShort: true,
					Pretest: func(b *testing.B) error {
						_, err := jsonReader.Seek(0, 0)
						return err
					},
					Test: func(b *testing.B) error {
						_, err := jwt.ParseReader(jsonReader)
						return err
					},
				},
				{
					Name: "json.Unmarshal",
					Test: func(b *testing.B) error {
						return json.Unmarshal(jsonBuf, &v)
					},
				},
			}
			for _, tc := range testcases {
				tc.Run(b)
			}
		})
	})
}
