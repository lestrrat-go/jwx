package jwt

import (
	"github.com/pkg/errors"
)

func (l *StringList) Accept(v interface{}) error {
	switch x := v.(type) {
	case string:
		*l = StringList([]string{x})
	case []string:
		*l = StringList(x)
	case []interface{}:
		list := make(StringList, len(x))
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
