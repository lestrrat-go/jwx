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
	var zero T
	v, ok := key.Field(name)
	if !ok {
		return zero, fmt.Errorf(`jwk.Get: field %q not found`, name)
	}
	result, ok := v.(T)
	if !ok {
		return zero, fmt.Errorf(`jwk.Get: field %q is %T, not %T`, name, v, zero)
	}
	return result, nil
}
