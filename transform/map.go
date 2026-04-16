package transform

import (
	"fmt"
)

// Mappable is an interface that defines methods required when converting
// a jwx structure into a map[string]any.
//
// EXPERIMENTAL: This API is experimental and its interface and behavior is
// subject to change in future releases. This API is not subject to semver
// compatibility guarantees.
type Mappable interface {
	Field(key string) (any, bool)
	Keys() []string
}

// AsMap takes the specified Mappable object and populates the map
// `dst` with the key-value pairs from the Mappable object.
// Many objects in jwe, jwk, jws, and jwt packages including
// `jwt.Token`, `jwk.Key`, `jws.Header`, etc.
//
// The values stored in `dst` are the exact values returned by `m.Field()`.
// Mutable values such as slices, maps, and pointers may therefore be live
// aliases to the original object's backing storage. AsMap is not a deep-copy
// or snapshot helper.
//
// EXPERIMENTAL: This API is experimental and its interface and behavior is
// subject to change in future releases. This API is not subject to semver
// compatibility guarantees.
func AsMap(m Mappable, dst map[string]any) error {
	if dst == nil {
		return fmt.Errorf("transform.AsMap: destination map cannot be nil")
	}

	for _, k := range m.Keys() {
		if v, ok := m.Field(k); ok {
			dst[k] = v
		}
	}

	return nil
}
