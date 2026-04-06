package jwe

import "fmt"

// Get is a type-safe generic accessor that retrieves a header field value.
// It returns the value and an error if the field does not exist or cannot be
// converted to type T.
//
// Usage:
//
//	kid, err := jwe.Get[string](headers, jwe.KeyIDKey)
//	custom, err := jwe.Get[MyType](headers, "my-custom-field")
func Get[T any](headers Headers, name string) (T, error) {
	var dst T
	if err := headers.Get(name, &dst); err != nil {
		return dst, fmt.Errorf(`jwe.Get: %w`, err)
	}
	return dst, nil
}
