package jwk_test

import (
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

func makeKeySet(b *testing.B, n int) jwk.Set {
	b.Helper()
	set := jwk.NewSet()
	for i := range n {
		key, err := jwk.Import[jwk.Key](fmt.Appendf(nil, "secret-key-value-%04d", i))
		if err != nil {
			b.Fatalf("failed to create key: %v", err)
		}
		if err := key.Set(jwk.KeyIDKey, fmt.Sprintf("kid-%04d", i)); err != nil {
			b.Fatalf("failed to set key id: %v", err)
		}
		if err := set.AddKey(key); err != nil {
			b.Fatalf("failed to add key: %v", err)
		}
	}
	return set
}

func BenchmarkLookupKeyID(b *testing.B) {
	for _, size := range []int{1, 10, 100} {
		set := makeKeySet(b, size)

		midKID := fmt.Sprintf("kid-%04d", size/2)
		b.Run(fmt.Sprintf("size=%d/mid", size), func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				key, ok := set.LookupKeyID(midKID)
				if !ok || key == nil {
					b.Fatal("key not found")
				}
			}
		})

		endKID := fmt.Sprintf("kid-%04d", size-1)
		b.Run(fmt.Sprintf("size=%d/end", size), func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				key, ok := set.LookupKeyID(endKID)
				if !ok || key == nil {
					b.Fatal("key not found")
				}
			}
		})
	}
}
