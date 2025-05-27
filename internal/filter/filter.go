// Package filter provides common filtering functionality for JWX objects.
package filter

// Filterable is an interface that must be implemented by objects that can be filtered.
type Filterable[T any] interface {
	// Keys returns the names of all fields in the object.
	Keys() []string

	// Clone returns a deep copy of the object.
	Clone() (T, error)

	// Remove removes a field from the object.
	Remove(string) error
}

// Apply is a standalone function that provides type-safe filtering based on field names.
// It returns a new object with only the fields that match the specified names.
func Apply[T Filterable[T]](object T, names []string) (T, error) {
	return filterWith(object, names, true)
}

// Reject is a standalone function that provides type-safe filtering based on field names.
// It returns a new object with only the fields that DO NOT match the specified names.
func Reject[T Filterable[T]](object T, names []string) (T, error) {
	return filterWith(object, names, false)
}

// filterWith is an internal function used by both Apply and Reject functions
// to apply the filtering logic to an object. If include is true, only fields
// matching the names are included. If include is false, fields matching
// the names are excluded.
func filterWith[T Filterable[T]](object T, names []string, include bool) (T, error) {
	var zero T

	// Build a map for faster lookups
	fields := make(map[string]struct{}, len(names))
	for _, name := range names {
		fields[name] = struct{}{}
	}

	result, err := object.Clone()
	if err != nil {
		return zero, err
	}

	for _, k := range result.Keys() {
		if _, ok := fields[k]; (include && ok) || (!include && !ok) {
			continue
		}

		if err := result.Remove(k); err != nil {
			return zero, err
		}
	}

	return result, nil
}
