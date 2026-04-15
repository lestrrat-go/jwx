package jwt

import "fmt"

// Get is a type-safe generic accessor that retrieves a claim value from a token.
// It returns the value and an error if the claim does not exist or cannot be
// converted to type T.
//
// The returned error can be inspected with errors.Is / errors.AsType:
//
//   - ClaimNotFoundError is returned when the claim is absent.
//   - ClaimTypeMismatchError is returned when the claim is present
//     but its stored value is not assignable to T.
//
// Both errors are wrapped with a "jwt.Get:" prefix.
//
// Usage:
//
//	issuer, err := jwt.Get[string](token, jwt.IssuerKey)
//	custom, err := jwt.Get[MyType](token, "my-custom-claim")
func Get[T any](token Token, key string) (T, error) {
	var zero T
	v, ok := token.Field(key)
	if !ok {
		return zero, fmt.Errorf(`jwt.Get: %w`, ClaimNotFoundError{Name: key})
	}
	result, ok := v.(T)
	if !ok {
		return zero, fmt.Errorf(`jwt.Get: %w`, ClaimTypeMismatchError{Name: key, Got: v, Want: zero})
	}
	return result, nil
}
