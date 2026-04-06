package jwk

import "fmt"

// Get is a type-safe generic accessor that retrieves a field value from a key.
// It returns the value and an error if the field does not exist or cannot be
// converted to type T.
//
// Usage:
//
//	kid, err := jwk.Get[string](key, jwk.KeyIDKey)
//	custom, err := jwk.Get[MyType](key, "my-custom-field")
func Get[T any](key Key, name string) (T, error) {
	var dst T
	if err := key.Get(name, &dst); err != nil {
		return dst, fmt.Errorf(`jwk.Get: %w`, err)
	}
	return dst, nil
}
