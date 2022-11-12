package jwt

import "sync"

type TokenOptionSet uint64

var defaultOptions TokenOptionSet
var defaultOptionsMu sync.RWMutex

// TokenOption describes a single token option
type TokenOption uint64

const (
	FlattenAudience TokenOption = 1 << iota
	MaxPerTokenOption
)

func (o TokenOption) Value() uint64 {
	return uint64(o)
}

func (o TokenOptionSet) Value() uint64 {
	return uint64(o)
}

func DefaultOptionSet() TokenOptionSet {
	return TokenOptionSet(defaultOptions.Value())
}

func (o *TokenOptionSet) Enable(flag TokenOption) {
	*o = TokenOptionSet(o.Value() | uint64(flag))
}

func (o *TokenOptionSet) Disable(flag TokenOption) {
	*o = TokenOptionSet(o.Value() & ^uint64(flag))
}

func (o TokenOptionSet) IsEnabled(flag TokenOption) bool {
	return (uint64(o)&uint64(flag) == uint64(flag))
}
