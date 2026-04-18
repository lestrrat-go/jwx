package jwk

// Get is a type-safe generic accessor that retrieves a field value from a key.
// It returns the value and an error if the field does not exist or cannot be
// converted to type T.
//
// Usage:
//
//	kid, err := jwk.Get[string](key, jwk.KeyIDKey)
//	custom, err := jwk.Get[MyType](key, "my-custom-field")
//
// Callers that need to distinguish "field missing" from "field present
// but wrong type" should use [errors.Is] with [FieldNotFoundError]{} /
// [FieldTypeMismatchError]{}, or [errors.AsType] to recover the Name,
// Got, and Want fields.
func Get[T any](key Key, name string) (T, error) {
	var zero T
	v, ok := key.Field(name)
	if !ok {
		return zero, FieldNotFoundError{Name: name}
	}
	result, ok := v.(T)
	if !ok {
		return zero, FieldTypeMismatchError{Name: name, Got: v, Want: zero}
	}
	return result, nil
}
