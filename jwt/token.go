package jwt

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
)

// ClaimPair is the struct returned from the iterator used in
// the Claims() method
type ClaimPair struct {
	Name  string
	Value interface{}
}

// Claims returns an iterator that returns all claims
func (t *Token) Claims(octx context.Context) <-chan ClaimPair {
	if octx == nil {
		octx = context.Background()
	}

	ch := make(chan ClaimPair)
	go iterateClaims(octx, t, ch)
	return ch
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

func iterateClaims(ctx context.Context, t *Token, dst chan ClaimPair) {
	defer close(dst)

	for _, key := range standardClaims {
		value, ok := t.Get(key)
		if !ok {
			continue
		}

		select {
		case <-ctx.Done():
			return
		case dst <- ClaimPair{Name: key, Value: value}:
		}
	}

	for key, value := range t.privateClaims {
		select {
		case <-ctx.Done():
			return
		case dst <- ClaimPair{Name: key, Value: value}:
		}
	}
	fmt.Println("BAIL OUT")
}

// Visitor is used to examine each element of the token.
type Visitor interface {
	Visit(string, interface{}) error
}

// VisitFunc is a type of Visitor whose actual definition
// is a stateless function
type VisitFunc func(string, interface{}) error

// Visit implements the Visitor interace
func (fn VisitFunc) Visit(key string, value interface{}) error {
	return fn(key, value)
}

// Walk is a convenience function over the Claims() method
// that allows you to not deal with ClaimPair structs directly
func (t *Token) Walk(octx context.Context, v Visitor) error {
	if octx == nil {
		octx = context.Background()
	}

	wctx, cancel := context.WithCancel(octx)
	defer cancel()

	var seen int
	claimCount := t.Size()
	iter := t.Claims(octx)

	for loop := true; loop; {
		select {
		case <-wctx.Done():
			return wctx.Err()
		case pair, ok := <-iter:
			if ok {
				if err := v.Visit(pair.Name, pair.Value); err != nil {
					// TODO: allow functions to abort by detecting a specific error type
					return errors.Wrap(err, `failed to execute WalkFunc fn`)
				}
				continue
			}

			if seen < claimCount {
				return errors.Errorf("premature end of iteration (expected %d, got %d)", claimCount, seen)
			}
			loop = false
		}
	}
	return nil
}

// AsMap returns the representation of the token as a map[string]interface{}.
// If you are dealing with small tokens and you are not repeatedly calling
// this function, this will most likely suffice in many cases.
// If you are either dealing with large-ish tokens and/or using it in a
// code path where you may want to use the Claims() method directly
func (t *Token) AsMap(ctx context.Context) (map[string]interface{}, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	var seen int
	claimCount := t.Size()
	iter := t.Claims(ctx)
	m := make(map[string]interface{})

	for loop := true; loop; {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case pair, ok := <-iter:
			if ok {
				m[pair.Name] = pair.Value
				seen++
				continue
			}
			if seen < claimCount {
				return nil, errors.Errorf("premature end of iteration (expected %d, got %d)", claimCount, seen)
			}
			loop = false
		}
	}

	return m, nil
}
