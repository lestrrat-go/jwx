package types_test

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/internal/json"

	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/lestrrat-go/jwx/v3/jwt/internal/types"
	"github.com/stretchr/testify/require"
)

func TestDate(t *testing.T) {
	t.Run("Get from a nil NumericDate", func(t *testing.T) {
		var n *types.NumericDate
		require.Equal(t, time.Time{}, n.Get())
	})
	t.Run("MarshalJSON with a zero value", func(t *testing.T) {
		var n *types.NumericDate
		buf, err := json.Marshal(n)
		require.NoError(t, err, `json.Marshal against a zero value should succeed`)
		require.Equal(t, []byte(`null`), buf, `result should be null`)
	})

	// This test alters global behavior, and can't be ran in parallel
	t.Run("Accept values", func(t *testing.T) {
		// NumericDate allows assignment from various different Go types,
		// so that it's easier for the devs, and conversion to/from JSON
		testcases := []struct {
			Input     any
			Expected  time.Time
			Precision int
		}{
			{
				Input:    int64(127),
				Expected: time.Unix(127, 0).UTC(),
			},
			{
				Input:    int32(127),
				Expected: time.Unix(127, 0).UTC(),
			},
			{
				Input:    int16(127),
				Expected: time.Unix(127, 0).UTC(),
			},
			{
				Input:    int8(127),
				Expected: time.Unix(127, 0).UTC(),
			},
			{
				Input:    float32(127.11),
				Expected: time.Unix(127, 0).UTC(),
			},
			{
				Input:    float32(127.11),
				Expected: time.Unix(127, 0).UTC(),
			},
			{
				Input:    json.Number("127"),
				Expected: time.Unix(127, 0).UTC(),
			},
			{
				Input:    json.Number("127.11"),
				Expected: time.Unix(127, 0).UTC(),
			},
			{
				Input:     json.Number("127.11"),
				Expected:  time.Unix(127, 110000000).UTC(),
				Precision: 4,
			},
			{
				Input:     json.Number("127.110000011"),
				Expected:  time.Unix(127, 110000011).UTC(),
				Precision: 9,
			},
			{
				Input:     json.Number("127.110000011111"),
				Expected:  time.Unix(127, 110000011).UTC(),
				Precision: 9,
			},
		}

		for _, tc := range testcases {
			precision := tc.Precision
			t.Run(fmt.Sprintf("%v(type=%T, precision=%d)", tc.Input, tc.Input, precision), func(t *testing.T) {
				jwt.Settings(jwt.WithNumericDateParsePrecision(precision))

				t1 := jwt.New()
				err := t1.Set(jwt.IssuedAtKey, tc.Input)
				require.NoError(t, err)
				var v time.Time
				require.NoError(t, t1.Get(jwt.IssuedAtKey, &v), `t1.Get should succeed`)
				require.Equal(t, tc.Expected, v)
			})
		}
	})
}

func TestNumericDateNegative(t *testing.T) {
	oldPedantic, oldPrecision := types.Pedantic.Load(), types.ParsePrecision.Load()
	t.Cleanup(func() {
		types.Pedantic.Store(oldPedantic)
		types.ParsePrecision.Store(oldPrecision)
	})

	for _, pedantic := range []bool{false, true} {
		t.Run(fmt.Sprintf("pedantic=%t", pedantic), func(t *testing.T) {
			// The sign applies to the whole number, fraction included, and
			// digits beyond the parse precision round toward negative
			// infinity, the same way NumericDate.String() and time.Unix do.
			for _, tc := range []struct {
				input     string
				precision int
				want      time.Time
			}{
				{"-1", 9, time.Unix(-1, 0)},
				{"-1.5", 9, time.Unix(-2, 500000000)},
				{"-0.5", 9, time.Unix(-1, 500000000)},
				{"-0.000000001", 9, time.Unix(-1, 999999999)},
				{"-1.0000000005", 9, time.Unix(-2, 999999999)},
				{"-1.0005", 3, time.Unix(-2, 999000000)},
				{"-1.5000", 3, time.Unix(-2, 500000000)},
				{"-1.5", 0, time.Unix(-2, 0)},
				{"-0.5", 0, time.Unix(-1, 0)},
				{"-1.0", 0, time.Unix(-1, 0)},
				{"-9223372036854775808", 0, time.Unix(math.MinInt64, 0)},
			} {
				t.Run(fmt.Sprintf("Accept/%s/precision=%d", tc.input, tc.precision), func(t *testing.T) {
					jwt.Settings(
						jwt.WithNumericDateParsePedantic(pedantic),
						jwt.WithNumericDateParsePrecision(tc.precision),
					)
					var date types.NumericDate
					require.NoError(t, date.Accept(tc.input))
					require.Equal(t, tc.want.UTC(), date.Time)
				})
			}

			for _, tc := range []struct {
				data string
				want time.Time
			}{
				{"-1", time.Unix(-1, 0)},
				{"-1.5", time.Unix(-2, 500000000)},
				{"-0.5", time.Unix(-1, 500000000)},
				{"-0", time.Unix(0, 0)},
				{"-1.0000000005", time.Unix(-2, 999999999)},
				{"-2000000000.123456789", time.Unix(-2000000001, 876543211)},
				{"-1.5e0", time.Unix(-2, 500000000)},
			} {
				t.Run("UnmarshalJSON/"+tc.data, func(t *testing.T) {
					jwt.Settings(
						jwt.WithNumericDateParsePedantic(pedantic),
						jwt.WithNumericDateParsePrecision(9),
					)
					var date types.NumericDate
					require.NoError(t, date.UnmarshalJSON([]byte(tc.data)))
					require.Equal(t, tc.want.UTC(), date.Time)
				})
			}

			// A number must be a number all the way through: digits that the
			// parse precision would drop are still checked
			for _, input := range []string{"1.5abc", "-1.5abc", "--1", "-", "-.5", "+1", "1.5.5"} {
				t.Run("reject/"+input, func(t *testing.T) {
					jwt.Settings(
						jwt.WithNumericDateParsePedantic(pedantic),
						jwt.WithNumericDateParsePrecision(1),
					)
					var date types.NumericDate
					require.Error(t, date.Accept(input))
				})
			}
		})
	}

	t.Run("RFC3339 fallback still applies without pedantic", func(t *testing.T) {
		jwt.Settings(
			jwt.WithNumericDateParsePedantic(false),
			jwt.WithNumericDateParsePrecision(0),
		)
		var date types.NumericDate
		require.NoError(t, date.UnmarshalJSON([]byte(`"-1.5"`)))
		require.Equal(t, time.Unix(-2, 0).UTC(), date.Time)
		require.NoError(t, date.UnmarshalJSON([]byte(`"2026-10-04T00:00:00.5Z"`)))
		require.Equal(t, time.Date(2026, 10, 4, 0, 0, 0, 500000000, time.UTC), date.Time)
	})
}

func TestNumericDateDecimalJSON(t *testing.T) {
	oldPrecision := types.ParsePrecision.Load()
	t.Cleanup(func() { types.ParsePrecision.Store(oldPrecision) })
	jwt.Settings(jwt.WithNumericDateParsePrecision(int(types.MaxPrecision)))

	// Plain JSON numbers are parsed without float64, which would round
	// away the last digits of these
	for _, tc := range []struct {
		data string
		want time.Time
	}{
		{"2000000000.123456789", time.Unix(2000000000, 123456789)},
		{"9007199254740993.5", time.Unix(9007199254740993, 500000000)},
		{"9007199254740993", time.Unix(9007199254740993, 0)},
		{"-9007199254740993", time.Unix(-9007199254740993, 0)},
		{"2e9", time.Unix(2000000000, 0)},
	} {
		t.Run(tc.data, func(t *testing.T) {
			var date types.NumericDate
			require.NoError(t, date.UnmarshalJSON([]byte(tc.data)))
			require.Equal(t, tc.want.UTC(), date.Time)
		})
	}

	// Text that is not a JSON number is still rejected
	for _, data := range []string{"1.", "-", "-.5", ".5", "+1", "--1"} {
		t.Run("reject/"+data, func(t *testing.T) {
			var date types.NumericDate
			require.Error(t, date.UnmarshalJSON([]byte(data)))
		})
	}
}
