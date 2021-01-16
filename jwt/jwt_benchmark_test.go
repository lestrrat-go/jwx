package jwt_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/internal/jwxtest"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
)

func BenchmarkJWTParse(b *testing.B) {
	alg := jwa.RS256

	key, err := jwxtest.GenerateRsaJwk()
	if err != nil {
		b.Fatal(err)
	}

	t1 := jwt.New()
	signed, err := jwt.Sign(t1, alg, key)
	if err != nil {
		b.Fatal(err)
	}

	signedString := string(signed)
	b.Run("ParseString", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			t2, err := jwt.ParseString(signedString)
			if err != nil {
				b.Fatal(err)
			}
			_ = t2
		}
	})
	b.Run("ParseBytes", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			t2, err := jwt.ParseBytes(signed)
			if err != nil {
				b.Fatal(err)
			}
			_ = t2
		}
	})
}
