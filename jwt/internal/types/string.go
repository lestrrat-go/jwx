package types

import (
	"fmt"
	"sync/atomic"

	"github.com/lestrrat-go/jwx/v2/internal/json"
)

type Audience []string

func (aud Audience) MarshalJSON() ([]byte, error) {
	var val interface{}
	if len(aud) == 1 && atomic.LoadUint32(&json.FlattenAudience) == 1 {
		val = aud[0]
	} else {
		val = []string(aud) // convert to raw []string to avoid recursion
	}
	return json.Marshal(val)
}

func (aud Audience) GetValue() []string {
	return []string(aud)
}

func (aud *Audience) AcceptValue(v interface{}) error {
	switch x := v.(type) {
	case string:
		*aud = Audience([]string{x})
	case []string:
		*aud = Audience(x)
	case []interface{}:
		list := make(Audience, len(x))
		for i, e := range x {
			if s, ok := e.(string); ok {
				list[i] = s
				continue
			}
			return fmt.Errorf(`invalid list element type %T`, e)
		}
		*aud = list
	default:
		return fmt.Errorf(`invalid type: %T`, v)
	}
	return nil
}

func (aud *Audience) UnmarshalJSON(data []byte) error {
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return fmt.Errorf(`failed to unmarshal data: %w`, err)
	}
	return aud.AcceptValue(v)
}
