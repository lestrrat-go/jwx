package jwt

import (
	"encoding/json"
	"reflect"
	"time"
)

type StringList []string

// NumericDate represents the date format used in the 'nbf' claim
type NumericDate struct {
	time.Time
}

func (l *StringList) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch value := v.(type) {
	case []interface{}:
		list := make([]string,0,len(value))
		for _, v := range value {
			element, ok := v.(string)
			if ok {
				list = append(list, element)
			}
		}
		*l = list
	case string:
		*l = []string{value}
	default:
		return &json.InvalidUnmarshalError{reflect.TypeOf(v)}
	}

	return nil
}