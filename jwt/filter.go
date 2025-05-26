package jwt

import (
	"sync"

	"github.com/lestrrat-go/jwx/v3/internal/filter"
)

// TokenFilter is an interface that allows users to filter JWT claims.
// It provides two methods: Filter and Reject; Filter returns a new token with only
// the claims that match the filter criteria, while Reject returns a new token with
// only the claims that DO NOT match the filter.
type TokenFilter interface {
	Filter(token Token) (Token, error)
	Reject(token Token) (Token, error)
}

// StandardClaimsFilter returns a TokenFilter that filters out standard JWT claims.
//
// You can use this filter to create tokens that either only has standard claims
// or only custom claims. If you need to configure the filter more precisely, consider
// using the ClaimNameFilter directly.
func StandardClaimsFilter() TokenFilter {
	return stdClaimsFilter
}

// ClaimNameFilter is an object that allows you to filter JWT claims by claim names.
type ClaimNameFilter struct {
	names []string
	mu    sync.RWMutex
}

// NewClaimNameFilter creates a new ClaimNameFilter with the specified claim names.
func NewClaimNameFilter(names ...string) *ClaimNameFilter {
	return &ClaimNameFilter{
		names: names,
	}
}

// Filter returns a new token with only the claims that match the filter.
func (cn *ClaimNameFilter) Filter(token Token) (Token, error) {
	cn.mu.RLock()
	names := make([]string, len(cn.names))
	copy(names, cn.names)
	cn.mu.RUnlock()

	result, err := filter.FilterWith[Token](token, names)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// Reject returns a new token with only the claims that DO NOT match the filter.
func (cn *ClaimNameFilter) Reject(token Token) (Token, error) {
	cn.mu.RLock()
	names := make([]string, len(cn.names))
	copy(names, cn.names)
	cn.mu.RUnlock()

	result, err := filter.RejectWith[Token](token, names)
	if err != nil {
		return nil, err
	}

	return result, nil
}
