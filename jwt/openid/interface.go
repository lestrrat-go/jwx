package openid

import (
	"github.com/lestrrat-go/iter/mapiter"
	"github.com/lestrrat-go/jwx/internal/iter"
	"github.com/lestrrat-go/jwx/internal/json"
)

type ClaimPair = mapiter.Pair
type Iterator = mapiter.Iterator
type Visitor = iter.MapVisitor
type VisitorFunc = iter.MapVisitorFunc

// DecodeCtx is an interface for objects that needs that extra something
// when decoding JSON into an object.
type DecodeCtx interface {
	Registry() *json.Registry
}

// TokenWithDecodeCtx is used to differentiate objects that can carry extra
// decoding hints and those who can't.
type TokenWithDecodeCtx interface {
	DecodeCtx() DecodeCtx
	SetDecodeCtx(DecodeCtx)
}
