package jwt_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/require"
)

func TestParseRejectsOverflowingNumericDates(t *testing.T) {
	key := []byte("numeric-date-range-regression-test")
	for _, claim := range []string{jwt.NotBeforeKey, jwt.IssuedAtKey, jwt.ExpirationKey} {
		t.Run(claim, func(t *testing.T) {
			for _, value := range []string{"9223372036854775807", "9.22337198e18"} {
				signed, err := jws.Sign(fmt.Appendf(nil, `{"%s":%s}`, claim, value), jws.WithKey(jwa.HS256(), key))
				require.NoError(t, err)
				// Establish that this is a valid signature, not a forgery.
				_, err = jws.Verify(signed, jws.WithKey(jwa.HS256(), key))
				require.NoError(t, err)
				for _, options := range [][]jwt.ParseOption{
					{jwt.WithKey(jwa.HS256(), key)},
					{jwt.WithKey(jwa.HS256(), key), jwt.WithValidate(false)},
					{jwt.WithKey(jwa.HS256(), key), jwt.WithToken(jwt.New()), jwt.WithValidate(false)},
				} {
					_, err := jwt.Parse(signed, options...)
					require.Error(t, err, "overflow must fail during parsing, independently of validation")
				}
			}
		})
	}

	// A representable future nbf must still fail validation normally.
	signed, err := jws.Sign([]byte(`{"nbf":1791075600}`), jws.WithKey(jwa.HS256(), key))
	require.NoError(t, err)
	_, err = jwt.Parse(signed, jwt.WithKey(jwa.HS256(), key),
		jwt.WithClock(jwt.ClockFunc(func() time.Time { return time.Unix(1791072000, 0) })),
		jwt.WithAcceptableSkew(0))
	require.ErrorIs(t, err, jwt.TokenNotYetValidError{})
}
