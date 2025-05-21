package jwt

import "sync"

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

func NewClaimNameFilter(names ...string) *ClaimNameFilter {
	return &ClaimNameFilter{
		names: names,
	}
}

func filter(cn *ClaimNameFilter, token Token, include bool) (Token, error) {
	cn.mu.RLock()
	claims := make(map[string]struct{}, len(cn.names))
	for _, name := range cn.names {
		claims[name] = struct{}{}
	}
	cn.mu.RUnlock()

	result, err := token.Clone()
	if err != nil {
		return nil, err
	}

	for _, k := range result.Keys() {
		if _, ok := claims[k]; (include && ok) || (!include && !ok) {
			continue
		}
		if err := result.Remove(k); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (cn *ClaimNameFilter) Filter(token Token) (Token, error) {
	return filter(cn, token, true)
}

func (cn *ClaimNameFilter) Reject(token Token) (Token, error) {
	return filter(cn, token, false)
}
