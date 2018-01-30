package jwt

import (
	"encoding/json"
	"time"

	"github.com/pkg/errors"
)

func (n *NumericDate) Get() time.Time {
	if n == nil {
		return time.Time{}
	}
	return n.Time
}

func (n *NumericDate) Accept(v interface{}) error {
	switch x := v.(type) {
	case json.Number:
		intval, err := x.Int64()
		if err != nil {
			return errors.Wrap(err, `failed to convert json value to int64`)
		}
		n.Time = time.Unix(intval, 0)
	case int64:
		n.Time = time.Unix(x, 0)
	case int32:
		n.Time = time.Unix(int64(x), 0)
	case int16:
		n.Time = time.Unix(int64(x), 0)
	case int8:
		n.Time = time.Unix(int64(x), 0)
	case int:
		n.Time = time.Unix(int64(x), 0)
	case float32:
		n.Time = time.Unix(int64(x), 0)
	case float64:
		n.Time = time.Unix(int64(x), 0)
	case time.Time:
		n.Time = x
	default:
		return errors.Errorf(`invalid type %T`, v)
	}
	return nil
}

// MarshalJSON generates JSON representation of this instant
func (n NumericDate) MarshalJSON() ([]byte, error) {
	return json.Marshal(n.UTC().Unix())
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

	*n = NumericDate{Time: time.Unix(intval, 0)}
	return nil
}
