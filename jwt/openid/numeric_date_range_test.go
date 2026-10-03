package openid_test

import (
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/lestrrat-go/jwx/v4/jwt/openid"
	"github.com/stretchr/testify/require"
)

func TestOpenIDRejectsOverflowingNumericDates(t *testing.T) {
	for _, claim := range []string{jwt.ExpirationKey, jwt.IssuedAtKey, jwt.NotBeforeKey, openid.UpdatedAtKey} {
		t.Run(claim, func(t *testing.T) {
			for _, value := range []string{"9223372036854775807", "9.22337198e18"} {
				token := openid.New()
				require.Error(t, json.Unmarshal(fmt.Appendf(nil, `{"%s":%s}`, claim, value), token))
			}
		})
	}
}
