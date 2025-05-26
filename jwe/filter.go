package jwe

import (
	"sync"

	"github.com/lestrrat-go/jwx/v3/internal/filter"
)

// HeaderFilter is an interface that allows users to filter JWE header fields.
// It provides two methods: Filter and Reject; Filter returns a new header with only
// the fields that match the filter criteria, while Reject returns a new header with
// only the fields that DO NOT match the filter.
type HeaderFilter interface {
	Filter(header Headers) (Headers, error)
	Reject(header Headers) (Headers, error)
}

// StandardHeadersFilter returns a HeaderFilter that filters out standard JWE header fields.
//
// You can use this filter to create headers that either only have standard fields
// or only custom fields.
//
// If you need to configure the filter more precisely, consider
// using the HeaderNameFilter directly.
func StandardHeadersFilter() HeaderFilter {
	return stdHeadersFilter
}

// These are the standard field names defined in the JWE specification
var standardHeaderNames = []string{
	AgreementPartyUInfoKey,
	AgreementPartyVInfoKey,
	AlgorithmKey,
	CompressionKey,
	ContentEncryptionKey,
	ContentTypeKey,
	CriticalKey,
	EphemeralPublicKeyKey,
	JWKKey,
	JWKSetURLKey,
	KeyIDKey,
	TypeKey,
	X509CertChainKey,
	X509CertThumbprintKey,
	X509CertThumbprintS256Key,
	X509URLKey,
}

var stdHeadersFilter = NewHeaderNameFilter(standardHeaderNames...)

// HeaderNameFilter is an object that allows you to filter JWE header fields by field names.
type HeaderNameFilter struct {
	names []string
	mu    sync.RWMutex
}

// NewHeaderNameFilter creates a new HeaderNameFilter with the specified field names.
func NewHeaderNameFilter(names ...string) *HeaderNameFilter {
	return &HeaderNameFilter{
		names: names,
	}
}

// Filter returns a new header with only the fields that match the filter.
func (hn *HeaderNameFilter) Filter(header Headers) (Headers, error) {
	hn.mu.RLock()
	names := make([]string, len(hn.names))
	copy(names, hn.names)
	hn.mu.RUnlock()

	result, err := filter.FilterWith[Headers](header, names)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// Reject returns a new header with only the fields that DO NOT match the filter.
func (hn *HeaderNameFilter) Reject(header Headers) (Headers, error) {
	hn.mu.RLock()
	names := make([]string, len(hn.names))
	copy(names, hn.names)
	hn.mu.RUnlock()

	result, err := filter.RejectWith[Headers](header, names)
	if err != nil {
		return nil, err
	}

	return result, nil
}
