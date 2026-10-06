package jws_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
)

func BenchmarkMarshalFlattened(b *testing.B) {
	b.ReportAllocs()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	payload := []byte(`{"iss":"bench","sub":"test","aud":"perf","exp":9999999999}`)
	signed, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), key))
	if err != nil {
		b.Fatal(err)
	}

	msg, err := jws.Parse(signed)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for b.Loop() {
		_, err := msg.MarshalJSON()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMarshalFull(b *testing.B) {
	b.ReportAllocs()

	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	payload := []byte(`{"iss":"bench","sub":"test","aud":"perf","exp":9999999999}`)
	signed, err := jws.Sign(payload,
		jws.WithJSON(),
		jws.WithKey(jwa.ES256(), key1),
		jws.WithKey(jwa.ES256(), key2),
	)
	if err != nil {
		b.Fatal(err)
	}

	msg, err := jws.Parse(signed)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for b.Loop() {
		_, err := msg.MarshalJSON()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyJSONHeaderUnion(b *testing.B) {
	key := bytes.Repeat([]byte{42}, 32)
	protected := `{"alg":"HS256"}`
	for _, general := range []bool{false, true} {
		name := "flattened"
		if general {
			name = "general"
		}
		b.Run(name, func(b *testing.B) {
			wire := headerUnionJWS(b, &protected, nil, general, false)
			options := []jws.VerifyOption{jws.WithKey(jwa.HS256(), key)}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				got, err := jws.Verify(wire, options...)
				if err != nil {
					b.Fatal(err)
				}
				if !bytes.Equal(got, []byte("payload")) {
					b.Fatal("unexpected verified payload")
				}
			}
		})
	}
}
