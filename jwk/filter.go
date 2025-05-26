package jwk

import "sync"

// KeyFilter is an interface that allows users to filter JWK key fields.
// It provides two methods: Filter and Reject; Filter returns a new key with only
// the fields that match the filter criteria, while Reject returns a new key with
// only the fields that DO NOT match the filter.
type KeyFilter interface {
	Filter(key Key) (Key, error)
	Reject(key Key) (Key, error)
}

// StandardFieldsFilter returns a KeyFilter that filters out standard JWK fields.
//
// You can use this filter to create keys that either only has standard fields
// or only custom fields (note that some standard fields such as `kty` cannot be removed
// because in this library it is a characteristic of the object and not a data field).
//
// If you need to configure the filter more precisely, consider
// using the FieldNameFilter directly.
func StandardFieldsFilter() KeyFilter {
	return stdFieldsFilter
}

// These are the standard field names defined in the JWK specification
var standardFieldNames = []string{
	KeyTypeKey,
	KeyUsageKey,
	KeyOpsKey,
	AlgorithmKey,
	KeyIDKey,
	X509URLKey,
	X509CertChainKey,
	X509CertThumbprintKey,
	X509CertThumbprintS256Key,
}

var stdFieldsFilter = NewFieldNameFilter(standardFieldNames...)

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

// filter is an internal function used by both Filter and Reject methods
// to apply the filtering logic to a key. If include is true, only fields
// matching the filter are included. If include is false, fields matching
// the filter are excluded.
func filter(fn *FieldNameFilter, key Key, include bool) (Key, error) {
	fn.mu.RLock()
	fields := make(map[string]struct{}, len(fn.names))
	for _, name := range fn.names {
		fields[name] = struct{}{}
	}
	fn.mu.RUnlock()

	result, err := key.Clone()
	if err != nil {
		return nil, err
	}

	for _, k := range result.Keys() {
		if k == KeyTypeKey {
			// "kty" is a required field and cannot be removed
			continue
		}

		if _, ok := fields[k]; (include && ok) || (!include && !ok) {
			continue
		}

		if err := result.Remove(k); err != nil {
			return nil, err
		}
	}

	return result, nil
}

// Filter returns a new key with only the fields that match the filter.
func (fn *FieldNameFilter) Filter(key Key) (Key, error) {
	return filter(fn, key, true)
}

// Reject returns a new key with only the fields that DO NOT match the filter.
func (fn *FieldNameFilter) Reject(key Key) (Key, error) {
	return filter(fn, key, false)
}
