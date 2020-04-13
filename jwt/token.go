package jwt

import (
	"context"

	"github.com/lestrrat-go/iter/mapiter"
	"github.com/lestrrat-go/jwx/internal/iter"
)

// Iterate returns an iterator that returns all claims
func (t *Token) Iterate(octx context.Context) Iterator {
	if octx == nil {
		octx = context.Background()
	}

	ch := make(chan *ClaimPair)
	go iterateClaims(octx, t, ch)
	return mapiter.New(ch)
}

var standardClaims []string

func init() {
	standardClaims = make([]string, 7)
	standardClaims[0] = AudienceKey
	standardClaims[1] = ExpirationKey
	standardClaims[2] = IssuedAtKey
	standardClaims[3] = IssuerKey
	standardClaims[4] = JwtIDKey
	standardClaims[5] = NotBeforeKey
	standardClaims[6] = SubjectKey
}

func iterateClaims(ctx context.Context, t *Token, dst chan *ClaimPair) {
	defer close(dst)
	for _, key := range standardClaims {
		value, ok := t.Get(key)
		if !ok {
			continue
		}

		select {
		case <-ctx.Done():
			return
		case dst <- &ClaimPair{Key: key, Value: value}:
		}
	}

	for key, value := range t.privateClaims {
		select {
		case <-ctx.Done():
			return
		case dst <- &ClaimPair{Key: key, Value: value}:
		}
	}
}

// Walk is a convenience function over the Claims() method
// that allows you to not deal with ClaimPair structs directly
func (t *Token) Walk(ctx context.Context, visitor Visitor) error {
	return iter.WalkMap(ctx, t, visitor)
}

// AsMap returns the representation of the token as a map[string]interface{}.
// If you are dealing with small tokens and you are not repeatedly calling
// this function, this will most likely suffice in many cases.
// If you are either dealing with large-ish tokens and/or using it in a
// code path where you may want to use the Claims() method directly
func (t *Token) AsMap(ctx context.Context) (map[string]interface{}, error) {
	return iter.AsMap(ctx, t)
}
