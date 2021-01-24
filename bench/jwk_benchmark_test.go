package bench_test

import (
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/internal/jwxtest"
	"github.com/lestrrat-go/jwx/jwk"
)

func runJSONBench(b *testing.B, privkey jwk.Key) {
	b.Helper()

	privkey.Set("mykey", "1234567890")
	pubkey, err := jwk.PublicKeyOf(privkey)
	if err != nil {
		b.Fatal(err)
	}

	testcases := []struct {
		Name string
		Key  jwk.Key
	}{
		{Name: "PublicKey", Key: pubkey},
		{Name: "PrivateKey", Key: privkey},
	}

	for _, tc := range testcases {
		key := tc.Key
		b.Run(tc.Name, func(b *testing.B) {
			b.Run("jwk.Parse", func(b *testing.B) {
				buf, _ := json.Marshal(key)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := jwk.Parse(buf); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("json.Marshal", func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := json.Marshal(key); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

func BenchmarkJWK(b *testing.B) {
	b.Run("Serialization", func(b *testing.B) {
		b.Run("RSA", func(b *testing.B) {
			rsakey, _ := jwxtest.GenerateRsaJwk()
			runJSONBench(b, rsakey)
		})
		b.Run("EC", func(b *testing.B) {
			eckey, _ := jwxtest.GenerateEcdsaJwk()
			runJSONBench(b, eckey)
		})
		b.Run("Symmetric", func(b *testing.B) {
			symkey, _ := jwxtest.GenerateSymmetricJwk()
			runJSONBench(b, symkey)
		})
	})
}
