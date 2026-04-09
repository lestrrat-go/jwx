package jwt_test

import (
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
)

func BenchmarkJWTParse(b *testing.B) {
	rsaKey, err := jwxtest.GenerateRsaJwk()
	if err != nil {
		b.Fatal(err)
	}
	rsaPub, err := jwk.PublicKeyOf(rsaKey)
	if err != nil {
		b.Fatal(err)
	}

	hmacKey := []byte("supersecret-benchmark-key-12345!")

	tok := jwt.New()
	tok.Set(jwt.IssuedAtKey, time.Now().Unix())
	tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour).Unix())
	tok.Set(jwt.IssuerKey, "bench")

	for _, tc := range []struct {
		name      string
		alg       jwa.KeyAlgorithm
		signKey   any
		verifyKey any
	}{
		{"RS256", jwa.RS256(), rsaKey, rsaPub},
		{"HS256", jwa.HS256(), hmacKey, hmacKey},
	} {
		signed, err := jwt.Sign(tok, jwt.WithKey(tc.alg, tc.signKey))
		if err != nil {
			b.Fatal(err)
		}

		b.Run(tc.name+"/Parse+Verify", func(b *testing.B) {
			for b.Loop() {
				_, err := jwt.Parse(signed, jwt.WithKey(tc.alg, tc.verifyKey))
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run(tc.name+"/Parse+Verify+NoValidate", func(b *testing.B) {
			for b.Loop() {
				_, err := jwt.Parse(signed, jwt.WithKey(tc.alg, tc.verifyKey), jwt.WithValidate(false))
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
