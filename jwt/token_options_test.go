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
		// Vanilla set
		var opt jwt.TokenOptionSet

		// Initially, the option should be false
		require.False(t, opt.IsEnabled(jwt.FlattenAudience), `option FlattenAudience should be false`)

		// Flip this bit on
		opt.Enable(jwt.FlattenAudience)
		require.True(t, opt.IsEnabled(jwt.FlattenAudience), `option FlattenAudience should be true`)

		// Test copying
		var opt2 jwt.TokenOptionSet
		opt2.Set(opt)
		require.True(t, opt.IsEnabled(jwt.FlattenAudience), `option FlattenAudience should be true`)
		require.True(t, opt2.IsEnabled(jwt.FlattenAudience), `option FlattenAudience should be true`)

		// Flip this bit off
		opt.Disable(jwt.FlattenAudience)
		require.False(t, opt.IsEnabled(jwt.FlattenAudience), `option FlattenAudience should be false`)

		// The above should have not action at a distance effect on opt2
		require.True(t, opt2.IsEnabled(jwt.FlattenAudience), `option FlattenAudience should be true`)

		// Clear it
		opt2.Clear()
		require.False(t, opt2.IsEnabled(jwt.FlattenAudience), `option FlattenAudience should be false`)
	})
}
