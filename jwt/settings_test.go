package jwt_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/require"
)

// rfc3339DateToken is a raw JSON token whose "nbf" claim is encoded as an
// RFC3339 timestamp rather than epoch seconds. When the global pedantic flag
// is OFF, the lenient parser accepts it; when pedantic is ON, parsing fails.
const rfc3339DateToken = `{"nbf":"2020-01-01T00:00:00Z"}`

// pedanticEnabled reports whether the global numeric-date pedantic flag is
// currently in effect, observed behaviorally: a token carrying an RFC3339
// "nbf" only fails to parse when pedantic mode is enabled.
func pedanticEnabled(t *testing.T) bool {
	t.Helper()
	_, err := jwt.ParseInsecure([]byte(rfc3339DateToken))
	return err != nil
}

// TestSettingsNoClobber verifies that each jwt.Settings call adjusts only the
// options explicitly provided and leaves previously-set, unspecified settings
// untouched.
func TestSettingsNoClobber(t *testing.T) {
	// Settings mutates process-global state. Capture nothing fancy; just
	// restore the package defaults when we are done so we do not pollute
	// other tests.
	defer func() {
		require.NoError(t, jwt.Settings(
			jwt.WithNumericDateParsePedantic(false),
			jwt.WithFlattenAudience(false),
		))
	}()

	t.Run("pedantic survives unrelated flatten-audience call", func(t *testing.T) {
		require.NoError(t, jwt.Settings(jwt.WithNumericDateParsePedantic(true)))
		require.True(t, pedanticEnabled(t), `pedantic should be enabled`)

		// An unrelated Settings call must not reset pedantic.
		require.NoError(t, jwt.Settings(jwt.WithFlattenAudience(true)))
		require.True(t, pedanticEnabled(t), `pedantic should still be enabled after unrelated Settings call`)
		require.True(t, jwt.DefaultOptionSet().IsEnabled(jwt.FlattenAudience), `flatten audience should be enabled`)
	})

	t.Run("flatten-audience survives unrelated pedantic call", func(t *testing.T) {
		require.NoError(t, jwt.Settings(jwt.WithFlattenAudience(true)))
		require.True(t, jwt.DefaultOptionSet().IsEnabled(jwt.FlattenAudience), `flatten audience should be enabled`)

		// An unrelated Settings call must not reset flatten audience.
		require.NoError(t, jwt.Settings(jwt.WithNumericDateParsePedantic(false)))
		require.True(t, jwt.DefaultOptionSet().IsEnabled(jwt.FlattenAudience), `flatten audience should still be enabled after unrelated Settings call`)
	})
}
