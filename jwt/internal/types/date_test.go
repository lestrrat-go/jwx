package types_test

import (
	"fmt"
	"math"
	"strconv"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/internal/json"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/lestrrat-go/jwx/v4/jwt/internal/types"
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
				Input:    "127",
				Expected: time.Unix(127, 0).UTC(),
			},
			{
				Input:    "127.11",
				Expected: time.Unix(127, 0).UTC(),
			},
			{
				Input:     "127.11",
				Expected:  time.Unix(127, 110000000).UTC(),
				Precision: 4,
			},
			{
				Input:     "127.110000011",
				Expected:  time.Unix(127, 110000011).UTC(),
				Precision: 9,
			},
			{
				Input:     "127.110000011111",
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
				fieldV, ok := t1.Field(jwt.IssuedAtKey)
				require.True(t, ok, `t1.Field should succeed`)
				v := fieldV.(time.Time)
				require.Equal(t, tc.Expected, v)
			})
		}
	})
}

func TestNumericDateRejectsTimeOverflow(t *testing.T) {
	// Global parsing settings must not leak into parallel tests.
	oldPedantic := types.Pedantic.Load()
	types.Pedantic.Store(0)
	t.Cleanup(func() { types.Pedantic.Store(oldPedantic) })

	// time.Time stores seconds relative to year 1, rather than the Unix epoch.
	maxSeconds := int64(math.MaxInt64) + (time.Time{}).Unix()
	for _, seconds := range []int64{maxSeconds - 1, maxSeconds, maxSeconds + 1, math.MaxInt64} {
		t.Run(strconv.FormatInt(seconds, 10), func(t *testing.T) {
			valid := seconds <= maxSeconds
			for _, value := range []any{seconds, strconv.FormatInt(seconds, 10)} {
				t.Run(fmt.Sprintf("Accept/%T", value), func(t *testing.T) {
					var date types.NumericDate
					err := date.Accept(value)
					if !valid {
						require.Error(t, err)
						return
					}
					require.NoError(t, err)
					require.Equal(t, seconds, date.Unix())
					require.True(t, date.After(time.Unix(0, 0)))
				})
			}
			for _, data := range []string{strconv.FormatInt(seconds, 10), strconv.Quote(strconv.FormatInt(seconds, 10))} {
				t.Run("UnmarshalJSON/"+data, func(t *testing.T) {
					var date types.NumericDate
					err := date.UnmarshalJSON([]byte(data))
					if !valid {
						require.Error(t, err)
						return
					}
					require.NoError(t, err)
					require.Equal(t, seconds, date.Unix())
				})
			}
		})
	}

	for _, value := range []any{float64(9.22337198e18), float32(9.22337198e18), math.Inf(1), math.NaN()} {
		var date types.NumericDate
		require.Error(t, date.Accept(value), "value %v (%T) must not become an overflowing date", value, value)
	}
	var date types.NumericDate
	require.Error(t, date.UnmarshalJSON([]byte("9.22337198e18")))

	// The fix must not impose an unrelated calendar-year or int32 limit.
	for _, seconds := range []int64{math.MinInt64, -1, 0, 2147483648, 253402300800} {
		require.NoError(t, date.Accept(seconds))
		require.Equal(t, seconds, date.Unix())
	}
}

func TestNumericDateOverflowDoesNotReplaceValue(t *testing.T) {
	var date types.NumericDate
	require.NoError(t, date.Accept(int64(1791072000)))
	original := date.Time
	require.Error(t, date.UnmarshalJSON([]byte("9223372036854775807")))
	require.Equal(t, original, date.Time)
	require.Error(t, date.Accept(int64(math.MaxInt64)))
	require.Equal(t, original, date.Time)
	require.Error(t, date.Accept(time.Unix(math.MaxInt64, 0)))
	require.Equal(t, original, date.Time)
}

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
