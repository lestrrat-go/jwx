package types_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/internal/json"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/lestrrat-go/jwx/v2/jwt/internal/types"
	"github.com/stretchr/testify/assert"
)

func TestDate(t *testing.T) {
	t.Run("Get from a nil NumericDate", func(t *testing.T) {
		var n *types.NumericDate
		if !assert.Equal(t, time.Time{}, n.Get()) {
			return
		}
	})
	t.Run("MarshalJSON with a zero value", func(t *testing.T) {
		var n *types.NumericDate
		buf, err := json.Marshal(n)
		if !assert.NoError(t, err, `json.Marshal against a zero value should succeed`) {
			return
		}

		if !assert.Equal(t, []byte(`null`), buf, `result should be null`) {
			return
		}
	})

	// This test alters global behavior, and can't be ran in parallel
	t.Run("Accept values", func(t *testing.T) {
		// NumericDate allows assignment from various different Go types,
		// so that it's easier for the devs, and conversion to/from JSON
		testcases := []struct {
			Input     interface{}
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
			tc := tc
			precision := tc.Precision
			t.Run(fmt.Sprintf("%v(type=%T, precision=%d)", tc.Input, tc.Input, precision), func(t *testing.T) {
				jwt.Settings(jwt.WithNumericDateParsePrecision(precision))

				t1 := jwt.New()
				err := t1.Set(jwt.IssuedAtKey, tc.Input)
				if !assert.NoError(t, err) {
					return
				}
				v, ok := t1.Get(jwt.IssuedAtKey)
				if !assert.True(t, ok) {
					return
				}
				realized := v.(time.Time)
				if !assert.Equal(t, tc.Expected, realized) {
					return
				}
			})
		}
	})
}
