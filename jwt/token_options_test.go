package jwt_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/require"
)

func TestTokenOptions(t *testing.T) {
	t.Run("Option names", func(t *testing.T) {
		for i := uint64(1); i < jwt.MaxPerTokenOption.Value(); i <<= 1 {
			t.Logf("%s", jwt.TokenOption(i))
		}
	})
	t.Run("Sanity", func(t *testing.T) {
		var opt jwt.TokenOptionSet

		require.False(t, opt.IsEnabled(jwt.FlattenAudience), `option FlattenAudience should be flase`)
		opt.Enable(jwt.FlattenAudience)
		require.True(t, opt.IsEnabled(jwt.FlattenAudience), `option FlattenAudience should be true`)
		opt.Disable(jwt.FlattenAudience)
		require.False(t, opt.IsEnabled(jwt.FlattenAudience), `option FlattenAudience should be flase`)
	})
}
