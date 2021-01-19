package bench_test

import (
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/jwk"
)

func BenchmarkJwkJSON(b *testing.B) {
	b.Run("EC", func(b *testing.B) {
		const s = `{"keys":
       [
         {"kty":"EC",
          "crv":"P-256",
          "key_ops": ["verify"],
          "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
          "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
          "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
				 }
       ]
}`
		buf := []byte(s)
		key, _ := jwk.Parse(buf)

		b.Run("Parse", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				jwk.Parse(buf)
			}
		})
		b.Run("Marshal", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				json.Marshal(key)
			}
		})
	})
}
