package types_test

import (
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/lestrrat-go/jwx/v4/jwt/internal/types"
	"github.com/stretchr/testify/require"
)

func TestPedanticNumericDateRequiresJSONNumber(t *testing.T) {
	oldPedantic, oldPrecision := types.Pedantic.Load(), types.ParsePrecision.Load()
	t.Cleanup(func() {
		types.Pedantic.Store(oldPedantic)
		types.ParsePrecision.Store(oldPrecision)
	})
	require.NoError(t, jwt.Settings(jwt.WithNumericDateParsePedantic(true), jwt.WithNumericDateParsePrecision(9)))

	for _, data := range []string{`"1791072000"`, `"1791072000.5"`, `"2026-10-04T00:00:00Z"`, `null`, `true`, `[]`, `{}`} {
		t.Run(data, func(t *testing.T) {
			var date types.NumericDate
			require.NoError(t, date.Accept(int64(1)))
			original := date.Time
			require.Error(t, date.UnmarshalJSON([]byte(data)))
			require.Equal(t, original, date.Time)
		})
	}
	for _, tc := range []struct {
		data string
		want time.Time
	}{
		{"1791072000", time.Unix(1791072000, 0).UTC()},
		{" 1791072000 ", time.Unix(1791072000, 0).UTC()},
		{"1791072000.5", time.Unix(1791072000, 500000000).UTC()},
		{"1.791072e9", time.Unix(1791072000, 0).UTC()},
		{"-1", time.Unix(-1, 0).UTC()},
	} {
		t.Run(tc.data, func(t *testing.T) {
			var date types.NumericDate
			require.NoError(t, date.UnmarshalJSON([]byte(tc.data)))
			require.Equal(t, tc.want, date.Time)
		})
	}

	// Pedantic parsing concerns wire types; Set/Accept still accept Go strings.
	var date types.NumericDate
	require.NoError(t, date.Accept("1791072000"))
	require.NoError(t, jwt.Settings(jwt.WithNumericDateParsePedantic(false)))
	for _, data := range []string{`"1791072000"`, `"2026-10-04T00:00:00Z"`} {
		require.NoError(t, date.UnmarshalJSON([]byte(data)))
	}
}
