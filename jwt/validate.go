package jwt

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/pkg/errors"
)

type Clock interface {
	Now() time.Time
}
type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time {
	return f()
}

func isSupportedTimeClaim(c string) error {
	switch c {
	case ExpirationKey, IssuedAtKey, NotBeforeKey:
		return nil
	}
	return errors.Errorf(`unsupported time claim %s`, strconv.Quote(c))
}

func timeClaim(t Token, clock Clock, c string) time.Time {
	switch c {
	case ExpirationKey:
		return t.Expiration()
	case IssuedAtKey:
		return t.IssuedAt()
	case NotBeforeKey:
		return t.NotBefore()
	case "":
		return clock.Now()
	}
	return time.Time{} // should *NEVER* reach here, but...
}

// Validate makes sure that the essential claims stand.
//
// See the various `WithXXX` functions for optional parameters
// that can control the behavior of this method.
func Validate(t Token, options ...ValidateOption) error {
	var issuer string
	var subject string
	var audience string
	var jwtid string
	var clock Clock = ClockFunc(time.Now)
	var skew time.Duration
	var deltas []delta
	requiredMap := make(map[string]struct{})
	claimValues := make(map[string]interface{})
	var validators = []Validator{
		ValidatorFunc(IsNbfValid),
	}
	for _, o := range options {
		//nolint:forcetypeassert
		switch o.Ident() {
		case identClock{}:
			clock = o.Value().(Clock)
		case identAcceptableSkew{}:
			skew = o.Value().(time.Duration)
		case identIssuer{}:
			issuer = o.Value().(string)
		case identSubject{}:
			subject = o.Value().(string)
		case identAudience{}:
			audience = o.Value().(string)
		case identJwtid{}:
			jwtid = o.Value().(string)
		case identRequiredClaim{}:
			requiredMap[o.Value().(string)] = struct{}{}
		case identTimeDelta{}:
			d := o.Value().(delta)
			deltas = append(deltas, d)
			if d.c1 != "" {
				if err := isSupportedTimeClaim(d.c1); err != nil {
					return err
				}
				requiredMap[d.c1] = struct{}{}
			}

			if d.c2 != "" {
				if err := isSupportedTimeClaim(d.c2); err != nil {
					return err
				}
				requiredMap[d.c2] = struct{}{}
			}
		case identClaim{}:
			claim := o.Value().(claimValue)
			claimValues[claim.name] = claim.value
		case identValidator{}:
			validators = append(validators, o.Value().(Validator))
		}
	}

	for c := range requiredMap {
		if _, ok := t.Get(c); !ok {
			return errors.Errorf(`required claim %s was not found`, c)
		}
	}

	for _, delta := range deltas {
		// We don't check if the claims already exist, because we already did that
		// by piggybacking on `required` check.
		t1 := timeClaim(t, clock, delta.c1).Truncate(time.Second)
		t2 := timeClaim(t, clock, delta.c2).Truncate(time.Second)
		if delta.less { // t1 - t2 <= delta.dur
			// t1 - t2 < delta.dur + skew
			if t1.Sub(t2) > delta.dur+skew {
				return errors.Errorf(`delta between %s and %s exceeds %s (skew %s)`, delta.c1, delta.c2, delta.dur, skew)
			}
		} else {
			if t1.Sub(t2) < delta.dur-skew {
				return errors.Errorf(`delta between %s and %s is less than %s (skew %s)`, delta.c1, delta.c2, delta.dur, skew)
			}
		}
	}

	// check for iss
	if len(issuer) > 0 {
		if v := t.Issuer(); v != issuer {
			return errors.New(`iss not satisfied`)
		}
	}

	// check for jti
	if len(jwtid) > 0 {
		if v := t.JwtID(); v != jwtid {
			return errors.New(`jti not satisfied`)
		}
	}

	// check for sub
	if len(subject) > 0 {
		if v := t.Subject(); v != subject {
			return errors.New(`sub not satisfied`)
		}
	}

	// check for aud
	if len(audience) > 0 {
		var found bool
		for _, v := range t.Audience() {
			if v == audience {
				found = true
				break
			}
		}
		if !found {
			return errors.New(`aud not satisfied`)
		}
	}

	// check for exp
	if tv := t.Expiration(); !tv.IsZero() && tv.Unix() != 0 {
		now := clock.Now().Truncate(time.Second)
		ttv := tv.Truncate(time.Second)
		if !now.Before(ttv.Add(skew)) {
			return errors.New(`exp not satisfied`)
		}
	}

	// check for iat
	if tv := t.IssuedAt(); !tv.IsZero() && tv.Unix() != 0 {
		now := clock.Now().Truncate(time.Second)
		ttv := tv.Truncate(time.Second)
		if now.Before(ttv.Add(-1 * skew)) {
			return errors.New(`iat not satisfied`)
		}
	}

	for name, expectedValue := range claimValues {
		if v, ok := t.Get(name); !ok || v != expectedValue {
			return fmt.Errorf(`%v not satisfied`, name)
		}
	}

	ctx := SetValidationCtxSkew(context.Background(), skew)
	ctx = SetValidationCtxClock(ctx, clock)
	for _, v := range validators {
		if err := v.Validate(ctx, t); err != nil {
			return err
		}
	}

	return nil
}

// Validator describes interface to validate Token.
type Validator interface {
	Validate(context.Context, Token) error
}

type ValidatorFunc func(context.Context, Token) error

func (vf ValidatorFunc) Validate(ctx context.Context, tok Token) error {
	return vf(ctx, tok)
}

type identValidationCtxClock struct{}
type identValidationCtxSkew struct{}

func SetValidationCtxClock(ctx context.Context, cl Clock) context.Context {
	return context.WithValue(ctx, identValidationCtxClock{}, cl)
}

// ValidationCtxClock returns the Clock object associated with
// the current validation context. This value will always be available
// during validation of tokens.
func ValidationCtxClock(ctx context.Context) Clock {
	return ctx.Value(identValidationCtxClock{}).(Clock)
}

func SetValidationCtxSkew(ctx context.Context, dur time.Duration) context.Context {
	return context.WithValue(ctx, identValidationCtxSkew{}, dur)
}

func ValidationCtxSkew(ctx context.Context) time.Duration {
	return ctx.Value(identValidationCtxSkew{}).(time.Duration)
}

// IsNbfValid is one of the default validators that will be executed.
// It does not need to be specified by users, but it exists as an
// exported field so that you can check what it does.
//
// The supplied context.Context object must have the "clock" and "skew"
// populated with appropriate values using SetValidationCtxClock() and
// SetValidationCtxSkew()
func IsNbfValid(ctx context.Context, t Token) error {
	clock := ValidationCtxClock(ctx) // MUST be populated
	if tv := t.NotBefore(); !tv.IsZero() && tv.Unix() != 0 {
		now := clock.Now().Truncate(time.Second)
		ttv := tv.Truncate(time.Second)
		skew := ValidationCtxSkew(ctx) // MUST be populated
		// now cannot be before t, so we check for now > t - skew
		if !now.Equal(ttv) && !now.After(ttv.Add(-1*skew)) {
			return errors.New(`nbf not satisfied`)
		}
	}
	return nil
}
