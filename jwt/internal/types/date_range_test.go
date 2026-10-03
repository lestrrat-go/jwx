package types_test

import (
	"fmt"
	"math"
	"strconv"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwt/internal/types"
	"github.com/stretchr/testify/require"
)

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
