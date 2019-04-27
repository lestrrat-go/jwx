package types_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jwt"
)

func TestDate(t *testing.T) {
	t.Run("Accept values", func(t *testing.T) {
		// NumericDate allows assignment from various different Go types,
		// so that it's easier for the devs, and conversion to/from JSON
		// use of "127" is just to allow use of int8's
		now := time.Unix(127, 0).UTC()
		for _, ut := range []interface{}{int64(127), int32(127), int16(127), int8(127), float32(127), float64(127), json.Number("127")} {
			t.Run(fmt.Sprintf("%T", ut), func(t *testing.T) {
				var t1 jwt.Token
				err := t1.Set(jwt.IssuedAtKey, ut)
				if err != nil {
					t.Fatalf("Failed to set IssuedAt value: %v", ut)
				}
				v, ok := t1.Get(jwt.IssuedAtKey)
				if !ok {
					t.Fatal("Failed to retrieve IssuedAt value")
				}
				realized := v.(time.Time)
				if !reflect.DeepEqual(now, realized) {
					t.Fatalf("Token time mistmatch. Expected:Realized (%v:%v)", now, realized)
				}
			})
		}
	})
}
