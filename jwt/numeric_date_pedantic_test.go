package jwt_test

import (
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/lestrrat-go/jwx/v4/jwt/internal/types"
	"github.com/stretchr/testify/require"
)

func TestParsePedanticNumericDateTypes(t *testing.T) {
	oldPedantic := types.Pedantic.Load()
	t.Cleanup(func() { types.Pedantic.Store(oldPedantic) })
	key := []byte("pedantic-numeric-date-regression-test")
	for _, claim := range []string{jwt.ExpirationKey, jwt.IssuedAtKey, jwt.NotBeforeKey} {
		for _, value := range []string{`"1791072000"`, `"1791072000.5"`, `"2026-10-04T00:00:00Z"`} {
			t.Run(claim+"/"+value, func(t *testing.T) {
				signed, err := jws.Sign(fmt.Appendf(nil, `{"%s":%s}`, claim, value), jws.WithKey(jwa.HS256(), key))
				require.NoError(t, err)
				for _, pedantic := range []bool{false, true} {
					require.NoError(t, jwt.Settings(jwt.WithNumericDateParsePedantic(pedantic)))
					for _, options := range [][]jwt.ParseOption{
						{jwt.WithKey(jwa.HS256(), key), jwt.WithValidate(false)},
						{jwt.WithKey(jwa.HS256(), key), jwt.WithToken(jwt.New()), jwt.WithValidate(false)},
					} {
						_, err := jwt.Parse(signed, options...)
						if pedantic {
							require.Error(t, err)
						} else {
							require.NoError(t, err)
						}
					}
				}
			})
		}
	}
}
