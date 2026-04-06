package jwt

import "fmt"

// Get is a type-safe generic accessor that retrieves a claim value from a token.
// It returns the value and an error if the claim does not exist or cannot be
// converted to type T.
//
// Usage:
//
//	issuer, err := jwt.Get[string](token, jwt.IssuerKey)
//	custom, err := jwt.Get[MyType](token, "my-custom-claim")
func Get[T any](token Token, key string) (T, error) {
	var zero T
	v, ok := token.Field(key)
	if !ok {
		return zero, fmt.Errorf(`jwt.Get: field %q not found`, key)
	}
	result, ok := v.(T)
	if !ok {
		return zero, fmt.Errorf(`jwt.Get: field %q is %T, not %T`, key, v, zero)
	}
	return result, nil
}
