package jws_test

import (
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
