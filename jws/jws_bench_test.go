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
