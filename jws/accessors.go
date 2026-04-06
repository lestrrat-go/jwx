package jws

import "fmt"

// Get is a type-safe generic accessor that retrieves a header field value.
// It returns the value and an error if the field does not exist or cannot be
// converted to type T.
//
// Usage:
//
//	kid, err := jws.Get[string](headers, jws.KeyIDKey)
//	custom, err := jws.Get[MyType](headers, "my-custom-field")
func Get[T any](headers Headers, name string) (T, error) {
	var zero T
	v, ok := headers.Field(name)
	if !ok {
		return zero, fmt.Errorf(`jws.Get: field %q not found`, name)
	}
	result, ok := v.(T)
	if !ok {
		return zero, fmt.Errorf(`jws.Get: field %q is %T, not %T`, name, v, zero)
	}
	return result, nil
}
