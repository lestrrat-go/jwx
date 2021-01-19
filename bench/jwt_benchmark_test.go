package bench_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/internal/jwxtest"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
)

func BenchmarkJWT(b *testing.B) {
	alg := jwa.RS256

	key, err := jwxtest.GenerateRsaJwk()
	if err != nil {
		b.Fatal(err)
	}

	t1 := jwt.New()
	t1.Set(jwt.IssuedAtKey, time.Now().Unix())
	t1.Set(jwt.ExpirationKey, time.Now().Add(time.Hour).Unix())
	signed, err := jwt.Sign(t1, alg, key)
	if err != nil {
		b.Fatal(err)
	}

	signedString := string(signed)
	signedReader := bytes.NewReader(signed)
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
	b.Run("Parse", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			t2, err := jwt.Parse(signed)
			if err != nil {
				b.Fatal(err)
			}
			_ = t2
		}
	})
	b.Run("ParseReader", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			signedReader.Seek(0, 0)
			b.StartTimer()
			t2, err := jwt.ParseReader(signedReader)
			if err != nil {
				b.Fatal(err)
			}
			_ = t2
		}
	})
	b.Run("json.Marshal", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = json.Marshal(t1)
		}
	})
}
