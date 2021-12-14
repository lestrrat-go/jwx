package jwk

import "regexp"

type RegexpWhitelist struct {
	patterns []*regexp.Regexp
}

func NewRegexpWhitelist() *RegexpWhitelist {
	return &RegexpWhitelist{}
}

func (w *RegexpWhitelist) Add(pat *regexp.Regexp) *RegexpWhitelist {
	w.patterns = append(w.patterns, pat)
	return w
}

// IsAlloed returns true if any of the patterns in the whitelist
// returns true.
func (w *RegexpWhitelist) IsAllowed(u string) bool {
	for _, pat := range w.patterns {
		if pat.MatchString(u) {
			return true
		}
	}
	return false
}

type MapWhitelist struct {
	store map[string]struct{}
}

func NewMapWhitelist() *MapWhitelist {
	return &MapWhitelist{store: make(map[string]struct{})}
}

func (w *MapWhitelist) Add(pat string) *MapWhitelist {
	w.store[pat] = struct{}{}
	return w
}

func (w *MapWhitelist) IsAllowed(u string) bool {
	_, b := w.store[u]
	return b
}

type WhitelistFunc func(string) bool

func (w WhitelistFunc) IsAllowed(u string) bool {
	return w(u)
}
