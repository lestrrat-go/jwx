package types_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/internal/json"

	"github.com/lestrrat-go/jwx/jwt"
	"github.com/lestrrat-go/jwx/jwt/internal/types"
	"github.com/stretchr/testify/assert"
)

func TestDate(t *testing.T) {
	t.Parallel()
	t.Run("Get from a nil NumericDate", func(t *testing.T) {
		t.Parallel()
		var n *types.NumericDate
		if !assert.Equal(t, time.Time{}, n.Get()) {
			return
		}
	})
	t.Run("MarshalJSON with a zero value", func(t *testing.T) {
		t.Parallel()
		var n *types.NumericDate
		buf, err := json.Marshal(n)
		if !assert.NoError(t, err, `json.Marshal against a zero value should succeed`) {
			return
		}

		if !assert.Equal(t, []byte(`null`), buf, `result should be null`) {
			return
		}
	})
	t.Run("Accept values", func(t *testing.T) {
		t.Parallel()
		// NumericDate allows assignment from various different Go types,
		// so that it's easier for the devs, and conversion to/from JSON
		// use of "127" is just to allow use of int8's
		now := time.Unix(127, 0).UTC()
		for _, ut := range []interface{}{int64(127), int32(127), int16(127), int8(127), float32(127), float64(127), json.Number("127")} {
			ut := ut
			t.Run(fmt.Sprintf("%T", ut), func(t *testing.T) {
				t.Parallel()
				t1 := jwt.New()
				err := t1.Set(jwt.IssuedAtKey, ut)
				if !assert.NoError(t, err) {
					return
				}
				v, ok := t1.Get(jwt.IssuedAtKey)
				if !assert.True(t, ok) {
					return
				}
				realized := v.(time.Time)
				if !assert.Equal(t, now, realized) {
					return
				}
			})
		}
	})
}
