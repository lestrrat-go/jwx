package jwt

import (
	"encoding/json"

	"github.com/pkg/errors"
)

func (l *stringList) Accept(v interface{}) error {
	switch x := v.(type) {
	case string:
		*l = stringList([]string{x})
	case []string:
		*l = stringList(x)
	case []interface{}:
		list := make([]string, len(x))
		for i, e := range x {
			if s, ok := e.(string); ok {
				list[i] = s
				continue
			}
			return errors.Errorf(`invalid list element type %T`, e)
		}
		*l = list
	default:
		return errors.Errorf(`invalid type: %T`, v)
	}
	return nil
}

func (l *stringList) UnmarshalJSON(data []byte) error {
	if data[0] == '[' {
		var s []string
		if err := json.Unmarshal(data, &s); err != nil {
			return errors.Wrap(err, `failed to unmarshal string list`)
		}
		*l = s
	} else {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return errors.Wrap(err, `failed to unmarshal string`)
		}
		*l = []string{s}
	}
	return nil
}
