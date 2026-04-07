package jws_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/stretchr/testify/require"
)

func FuzzParse(f *testing.F) {
	f.Add([]byte(`eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`))
	f.Add([]byte(`{"payload":"dGVzdA","signatures":[{"protected":"eyJhbGciOiJIUzI1NiJ9","signature":"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}]}`))
	f.Add([]byte(``))
	f.Add([]byte(`not-a-jws`))

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = jws.Parse(data)
	})
}

func FuzzSignAndVerify(f *testing.F) {
	f.Add([]byte(`hello world`))
	f.Add([]byte(`{"key":"value"}`))
	f.Add([]byte(``))
	f.Add([]byte(`The true sign of intelligence is not knowledge but imagination.`))

	key, err := jwk.Import[jwk.Key]([]byte(`abracadabra-secret-key-1234567890`))
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, payload []byte) {
		signed, err := jws.Sign(payload, jws.WithKey(jwa.HS256(), key))
		require.NoError(t, err)

		verified, err := jws.Verify(signed, jws.WithKey(jwa.HS256(), key))
		require.NoError(t, err)
		require.Equal(t, payload, verified)
	})
}
