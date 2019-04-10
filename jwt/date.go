package jwt

import (
	"encoding/json"
	"time"

	"github.com/pkg/errors"
)

func (n *NumericDate) Get() time.Time {
	if n == nil {
		return (time.Time{}).UTC()
	}
	return n.Time
}

func numericToTime(v interface{}, t *time.Time) bool {
	var n int64
	switch x := v.(type) {
	case int64:
		n = x
	case int32:
		n = int64(x)
	case int16:
		n = int64(x)
	case int8:
		n = int64(x)
	case int:
		n = int64(x)
	case float32:
		n = int64(x)
	case float64:
		n = int64(x)
	default:
		return false
	}

	*t = time.Unix(n, 0)
	return true
}

func (n *NumericDate) Accept(v interface{}) error {
	var t time.Time
	switch x := v.(type) {
	case json.Number:
		intval, err := x.Int64()
		if err != nil {
			return errors.Wrap(err, `failed to convert json value to int64`)
		}
		t = time.Unix(intval, 0)
	case time.Time:
		t = x
	default:
		if !numericToTime(v, &t) {
			return errors.Errorf(`invalid type %T`, v)
		}
	}
	n.Time = t.UTC()
	return nil
}

// MarshalJSON generates JSON representation of this instant
func (n NumericDate) MarshalJSON() ([]byte, error) {
	return json.Marshal(n.Unix())
}
