package openid_test

import (
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/lestrrat-go/jwx/v4/jwt/internal/types"
	"github.com/lestrrat-go/jwx/v4/jwt/openid"
	"github.com/stretchr/testify/require"
)

func TestOpenIDPedanticNumericDateTypes(t *testing.T) {
	oldPedantic := types.Pedantic.Load()
	t.Cleanup(func() { types.Pedantic.Store(oldPedantic) })
	require.NoError(t, jwt.Settings(jwt.WithNumericDateParsePedantic(true)))
	for _, claim := range []string{jwt.ExpirationKey, jwt.IssuedAtKey, jwt.NotBeforeKey, openid.UpdatedAtKey} {
		t.Run(claim, func(t *testing.T) {
			for _, value := range []string{`"1791072000"`, `"1791072000.5"`, `"2026-10-04T00:00:00Z"`} {
				require.Error(t, json.Unmarshal(fmt.Appendf(nil, `{"%s":%s}`, claim, value), openid.New()))
			}
			require.NoError(t, json.Unmarshal(fmt.Appendf(nil, `{"%s":1791072000}`, claim), openid.New()))
		})
	}
}
