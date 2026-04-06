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
	var dst T
	if err := token.Get(key, &dst); err != nil {
		return dst, fmt.Errorf(`jwt.Get: %w`, err)
	}
	return dst, nil
}
