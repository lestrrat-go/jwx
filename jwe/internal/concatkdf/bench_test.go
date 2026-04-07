package concatkdf_test

import (
	"crypto"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwe/internal/concatkdf"
)

func BenchmarkRead(b *testing.B) {
	hash := crypto.SHA256
	alg := []byte("A128CBC-HS256")
	z := make([]byte, 32)
	apu := []byte("Alice")
	apv := []byte("Bob")
	pubinfo := make([]byte, 4)
	privinfo := []byte{}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		kdf := concatkdf.New(hash, alg, z, apu, apv, pubinfo, privinfo)
		out := make([]byte, 32)
		if _, err := kdf.Read(out); err != nil {
			b.Fatal(err)
		}
	}
}
