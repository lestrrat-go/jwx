package transform

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
// Many objects in jwe, jwk, jws, and jwt packages including
// `jwt.Token`, `jwk.Key`, `jws.Header`, etc.
//
// This feature is experimental and may change or be removed in the future.
func AsMap(m Mappable, dst map[string]interface{}) error {
	if dst == nil {
		return fmt.Errorf("jwx.AsMap: destination map cannot be nil")
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
