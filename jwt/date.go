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

func (n *NumericDate) Accept(v interface{}) error {
	var t time.Time
	switch x := v.(type) {
	case json.Number:
		intval, err := x.Int64()
		if err != nil {
			return errors.Wrap(err, `failed to convert json value to int64`)
		}
		t = time.Unix(intval, 0)
	case int64:
		t = time.Unix(x, 0)
	case int32:
		t = time.Unix(int64(x), 0)
	case int16:
		t = time.Unix(int64(x), 0)
	case int8:
		t = time.Unix(int64(x), 0)
	case int:
		t = time.Unix(int64(x), 0)
	case float32:
		t = time.Unix(int64(x), 0)
	case float64:
		t = time.Unix(int64(x), 0)
	case time.Time:
		t = x
	default:
		return errors.Errorf(`invalid type %T`, v)
	}
	n.Time = t.UTC()
	return nil
}

// MarshalJSON generates JSON representation of this instant
func (n NumericDate) MarshalJSON() ([]byte, error) {
	return json.Marshal(n.Unix())
}

// UnmarshalJSON parses the JSON representation and initializes this NumericDate
func (n *NumericDate) UnmarshalJSON(data []byte) error {
	var v json.Number
	if err := json.Unmarshal(data, &v); err != nil {
		return errors.Wrap(err, `failed to decode jwt.NumericDate`)
	}

	intval, err := v.Int64()
	if err != nil {
		return errors.Wrap(err, `failed to coerce value into int64`)
	}
	*n = NumericDate{}
	return n.Accept(intval)
}
