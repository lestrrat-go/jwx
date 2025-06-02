package jwx

import "fmt"

// Mappable is an interface that defines methods required when converting
// a jwx structure into a map[string]interface{}.
//
// This feature is experimental and may change or be removed in the future.
type Mappable interface {
	Get(key string, dst interface{}) error
	Keys() []string
}

// AsMap takes the specified Mappable object and populates the map
// `dst` with the key-value pairs from the Mappable object.
// If `dst` is nil, it will be initialized to a new map.
//
// This feature is experimental and may change or be removed in the future.
func AsMap(m Mappable, dst map[string]interface{}) error {
	if dst == nil {
		dst = make(map[string]interface{})
	}

	for _, k := range m.Keys() {
		var val interface{}
		if err := m.Get(k, &val); err != nil {
			return fmt.Errorf(`jwx.AsMap: failed to get key %q: %w`, k, err)
		}
		dst[k] = val
	}

	return nil
}
