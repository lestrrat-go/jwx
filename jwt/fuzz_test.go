package jwt_test

import (
	"testing"
	"unicode/utf8"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/require"
)

func FuzzParse(f *testing.F) {
	f.Add([]byte(`eyJhbGciOiJub25lIn0.eyJpc3MiOiJ0ZXN0In0.`))
	f.Add([]byte(`{"iss":"test","sub":"user"}`))
	f.Add([]byte(``))
	f.Add([]byte(`not-a-token`))

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = jwt.ParseInsecure(data)
	})
}

func FuzzSignAndParse(f *testing.F) {
	f.Add(`test-issuer`, `test-subject`)
	f.Add(``, ``)
	f.Add("github.com/lestrrat-go/jwx", "user@example.com")

	key, err := jwk.Import[jwk.Key]([]byte(`abracadabra-secret-key-1234567890`))
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, issuer, subject string) {
		if !utf8.ValidString(issuer) || !utf8.ValidString(subject) {
			return
		}

		tok, err := jwt.NewBuilder().
			Issuer(issuer).
			Subject(subject).
			Build()
		require.NoError(t, err)

		signed, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256(), key))
		require.NoError(t, err)

		parsed, err := jwt.Parse(signed, jwt.WithKey(jwa.HS256(), key))
		require.NoError(t, err)

		gotIssuer, _ := parsed.Issuer()
		gotSubject, _ := parsed.Subject()
		require.Equal(t, issuer, gotIssuer)
		require.Equal(t, subject, gotSubject)
	})
}
