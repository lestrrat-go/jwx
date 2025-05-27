package jwk

import (
	"sync"

	"github.com/lestrrat-go/jwx/v3/internal/filter"
)

// KeyFilter is an interface that allows users to filter JWK key fields.
// It provides two methods: Filter and Reject; Filter returns a new key with only
// the fields that match the filter criteria, while Reject returns a new key with
// only the fields that DO NOT match the filter.
type KeyFilter interface {
	Filter(key Key) (Key, error)
	Reject(key Key) (Key, error)
}

// FieldNameFilter is an object that allows you to filter JWK fields by field names.
type FieldNameFilter struct {
	names []string
	mu    sync.RWMutex
}

// NewFieldNameFilter creates a new FieldNameFilter with the specified field names.
func NewFieldNameFilter(names ...string) *FieldNameFilter {
	return &FieldNameFilter{
		names: names,
	}
}

// Filter returns a new key with only the fields that match the filter.
func (fn *FieldNameFilter) Filter(key Key) (Key, error) {
	fn.mu.RLock()
	names := make([]string, len(fn.names))
	copy(names, fn.names)
	fn.mu.RUnlock()

	result, err := filter.Apply(key, names)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// Reject returns a new key with only the fields that DO NOT match the filter.
func (fn *FieldNameFilter) Reject(key Key) (Key, error) {
	fn.mu.RLock()
	names := make([]string, len(fn.names))
	copy(names, fn.names)
	fn.mu.RUnlock()

	result, err := filter.Reject(key, names)
	if err != nil {
		return nil, err
	}

	return result, nil
}
