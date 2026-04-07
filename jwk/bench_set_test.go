package jwk_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwk"
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

func BenchmarkKeyClone(b *testing.B) {
	rsaRaw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	rsaKey, err := jwk.Import[jwk.RSAPrivateKey](rsaRaw)
	if err != nil {
		b.Fatal(err)
	}

	ecRaw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	ecKey, err := jwk.Import[jwk.ECDSAPrivateKey](ecRaw)
	if err != nil {
		b.Fatal(err)
	}

	symKey, err := jwk.Import[jwk.SymmetricKey]([]byte("symmetric-key-value-for-benchmark"))
	if err != nil {
		b.Fatal(err)
	}

	b.Run("RSAPrivateKey", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			_, err := rsaKey.Clone()
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("ECDSAPrivateKey", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			_, err := ecKey.Clone()
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("SymmetricKey", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			_, err := symKey.Clone()
			if err != nil {
				b.Fatal(err)
			}
		}
	})
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
