package jws_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/require"
)

func BenchmarkCompact(b *testing.B) {
	b.ReportAllocs()

	key, err := jwxtest.GenerateRsaKey()
	require.NoError(b, err)

	payload := []byte(`{"iss":"bench","sub":"perf","aud":"test","exp":9999999999}`)
	signed, err := jws.Sign(payload, jws.WithKey(jwa.RS256(), key))
	require.NoError(b, err)

	msg, err := jws.Parse(signed)
	require.NoError(b, err)

	b.ResetTimer()
	for b.Loop() {
		_, err := jws.Compact(msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMarshalJSON(b *testing.B) {
	b.ReportAllocs()

	key, err := jwxtest.GenerateRsaKey()
	require.NoError(b, err)

	payload := []byte(`{"iss":"bench","sub":"perf","aud":"test","exp":9999999999}`)
	signed, err := jws.Sign(payload, jws.WithKey(jwa.RS256(), key))
	require.NoError(b, err)

	msg, err := jws.Parse(signed)
	require.NoError(b, err)

	b.ResetTimer()
	for b.Loop() {
		_, err := msg.MarshalJSON()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMarshalJSONMultiSig(b *testing.B) {
	b.ReportAllocs()

	rsaKey, err := jwxtest.GenerateRsaKey()
	require.NoError(b, err)
	ecKey, err := jwxtest.GenerateEcdsaKey(jwa.P256())
	require.NoError(b, err)

	payload := []byte(`{"iss":"bench","sub":"perf","aud":"test","exp":9999999999}`)
	signed, err := jws.Sign(payload,
		jws.WithJSON(),
		jws.WithKey(jwa.RS256(), rsaKey),
		jws.WithKey(jwa.ES256(), ecKey),
	)
	require.NoError(b, err)

	msg, err := jws.Parse(signed)
	require.NoError(b, err)

	b.ResetTimer()
	for b.Loop() {
		_, err := msg.MarshalJSON()
		if err != nil {
			b.Fatal(err)
		}
	}
}
