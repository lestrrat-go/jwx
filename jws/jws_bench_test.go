package jws_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v3/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
)

func BenchmarkCompact(b *testing.B) {
	// Setup: Create a key and payload
	key, err := jwxtest.GenerateRsaJwk()
	if err != nil {
		b.Fatal(err)
	}

	payload := []byte(`{"iss":"test-issuer","sub":"test-subject","aud":["test-audience"]}`)

	// Create a signed message
	signed, err := jws.Sign(payload, jws.WithKey(jwa.RS256(), key))
	if err != nil {
		b.Fatal(err)
	}

	// Parse the signed message to get a jws.Message
	msg, err := jws.Parse(signed)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := jws.Compact(msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// JWS Signing benchmarks for different algorithms
func BenchmarkSign(b *testing.B) {
	key, err := jwxtest.GenerateRsaKey()
	if err != nil {
		b.Fatal(err)
	}

	payload := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := jws.Sign(payload, jws.WithKey(jwa.RS256(), key))
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSignHMAC(b *testing.B) {
	key := []byte("abracadabra")
	payload := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := jws.Sign(payload, jws.WithKey(jwa.HS256(), key))
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSignECDSA(b *testing.B) {
	key, err := jwxtest.GenerateEcdsaKey(jwa.P256())
	if err != nil {
		b.Fatal(err)
	}

	payload := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), key))
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Signer creation and algorithm comparison benchmarks
func BenchmarkMakeSignerOriginal(b *testing.B) {
	key, err := jwxtest.GenerateRsaKey()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// This will internally call makeSigner multiple times
		_, err := jws.Sign([]byte("test payload"), jws.WithKey(jwa.RS256(), key))
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNewSigner(b *testing.B) {
	testCases := []struct {
		name string
		alg  jwa.SignatureAlgorithm
	}{
		{"HMAC", jwa.HS256()},
		{"RSA", jwa.RS256()},
		{"ECDSA", jwa.ES256()},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				signer, err := jws.NewSigner(tc.alg)
				if err != nil {
					b.Fatal(err)
				}
				_ = signer
			}
		})
	}
}

func BenchmarkSignerAlgorithms(b *testing.B) {
	hmacKey := []byte("secret")
	rsaKey, err := jwxtest.GenerateRsaKey()
	if err != nil {
		b.Fatal(err)
	}
	ecdsaKey, err := jwxtest.GenerateEcdsaKey(jwa.P256())
	if err != nil {
		b.Fatal(err)
	}
	testCases := []struct {
		name string
		alg  jwa.SignatureAlgorithm
		key  any
	}{
		{"HMAC", jwa.HS256(), hmacKey},
		{"RSA", jwa.RS256(), rsaKey},
		{"ECDSA", jwa.ES256(), ecdsaKey},
	}

	payload := []byte("Lorem Ipsum")
	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				signed, err := jws.Sign(payload, jws.WithKey(tc.alg, tc.key))
				if err != nil {
					b.Fatal(err)
				}
				_ = signed
			}
		})
	}
}
