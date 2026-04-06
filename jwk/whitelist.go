package jwk

import "regexp"

// Whitelist describes an interface for a URL whitelist that can be used
// to restrict URLs that jwk.Fetch() can access.
type Whitelist interface {
	IsAllowed(string) bool
}

// WhitelistFunc is a function-based implementation of Whitelist.
type WhitelistFunc func(string) bool

func (f WhitelistFunc) IsAllowed(u string) bool {
	return f(u)
}

// InsecureWhitelist is a whitelist that allows all URLs.
// Use this only in development/testing.
type InsecureWhitelist struct{}

func (InsecureWhitelist) IsAllowed(string) bool { return true }

// BlockAllWhitelist is a whitelist that blocks all URLs.
type BlockAllWhitelist struct{}

func (BlockAllWhitelist) IsAllowed(string) bool { return false }

// MapWhitelist is a whitelist backed by a map of allowed URLs.
type MapWhitelist struct {
	urls map[string]struct{}
}

func NewMapWhitelist() MapWhitelist {
	return MapWhitelist{urls: make(map[string]struct{})}
}

func (wl MapWhitelist) Add(u string) MapWhitelist {
	wl.urls[u] = struct{}{}
	return wl
}

func (wl MapWhitelist) IsAllowed(u string) bool {
	_, ok := wl.urls[u]
	return ok
}

// RegexpWhitelist is a whitelist that uses regular expressions to match URLs.
type RegexpWhitelist struct {
	patterns []*regexp.Regexp
}

func NewRegexpWhitelist() *RegexpWhitelist {
	return &RegexpWhitelist{}
}

func (wl *RegexpWhitelist) Add(pat *regexp.Regexp) *RegexpWhitelist {
	wl.patterns = append(wl.patterns, pat)
	return wl
}

func (wl *RegexpWhitelist) IsAllowed(u string) bool {
	for _, pat := range wl.patterns {
		if pat.MatchString(u) {
			return true
		}
	}
	return false
}
