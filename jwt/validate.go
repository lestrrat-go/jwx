package jwt

import (
	"context"
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
	var clock Clock = ClockFunc(time.Now)
	var skew time.Duration
	var deltas []delta
	var validators = []Validator{
		IsIssuedAtValid(),
		IsExpirationValid(),
		IsNbfValid(),
	}
	for _, o := range options {
		//nolint:forcetypeassert
		switch o.Ident() {
		case identClock{}:
			clock = o.Value().(Clock)
		case identAcceptableSkew{}:
			skew = o.Value().(time.Duration)
		case identIssuer{}:
			// backcompat: can be replaced with jwt.ClaimValueIs(...)
			validators = append(validators, ClaimValueIs(IssuerKey, o.Value().(string)))
		case identSubject{}:
			// backcompat: can be replaced with jwt.ClaimValueIs(...)
			validators = append(validators, ClaimValueIs(SubjectKey, o.Value().(string)))
		case identAudience{}:
			// backcompat: can be replaced with jwt.HasAudience(...)
			validators = append(validators, hasAudience(o.Value().(string)))
		case identJwtid{}:
			// backcompat: can be replaced with jwt.ClaimValueIs(...)
			validators = append(validators, ClaimValueIs(JwtIDKey, o.Value().(string)))
		case identRequiredClaim{}:
			// backcompat: can be replaced with jwt.IsRequired(...)
			validators = append(validators, IsRequired(o.Value().(string)))
		case identTimeDelta{}:
			d := o.Value().(delta)
			deltas = append(deltas, d)
			if d.c1 != "" {
				if err := isSupportedTimeClaim(d.c1); err != nil {
					return err
				}
				validators = append(validators, IsRequired(d.c1))
			}

			if d.c2 != "" {
				if err := isSupportedTimeClaim(d.c2); err != nil {
					return err
				}
				validators = append(validators, IsRequired(d.c2))
			}
		case identClaim{}:
			// backcompat: can be replaced with jwt.ClaimValueIs(...)
			claim := o.Value().(claimValue)
			validators = append(validators, ClaimValueIs(claim.name, claim.value))
		case identValidator{}:
			validators = append(validators, o.Value().(Validator))
		}
	}

	ctx := SetValidationCtxSkew(context.Background(), skew)
	ctx = SetValidationCtxClock(ctx, clock)
	for _, v := range validators {
		if err := v.Validate(ctx, t); err != nil {
			return err
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

func IsExpirationValid() Validator {
	return ValidatorFunc(isExpirationValid)
}

func isExpirationValid(ctx context.Context, t Token) error {
	if tv := t.Expiration(); !tv.IsZero() && tv.Unix() != 0 {
		clock := ValidationCtxClock(ctx) // MUST be populated
		now := clock.Now().Truncate(time.Second)
		ttv := tv.Truncate(time.Second)
		skew := ValidationCtxSkew(ctx) // MUST be populated
		if !now.Before(ttv.Add(skew)) {
			return errors.New(`exp not satisfied`)
		}
	}
	return nil
}

func IsIssuedAtValid() Validator {
	return ValidatorFunc(isIssuedAtValid)
}

func isIssuedAtValid(ctx context.Context, t Token) error {
	if tv := t.IssuedAt(); !tv.IsZero() && tv.Unix() != 0 {
		clock := ValidationCtxClock(ctx) // MUST be populated
		now := clock.Now().Truncate(time.Second)
		ttv := tv.Truncate(time.Second)
		skew := ValidationCtxSkew(ctx) // MUST be populated
		if now.Before(ttv.Add(-1 * skew)) {
			return errors.New(`iat not satisfied`)
		}
	}
	return nil
}

// IsNbfValid is one of the default validators that will be executed.
// It does not need to be specified by users, but it exists as an
// exported field so that you can check what it does.
//
// The supplied context.Context object must have the "clock" and "skew"
// populated with appropriate values using SetValidationCtxClock() and
// SetValidationCtxSkew()
func IsNbfValid() Validator {
	return ValidatorFunc(isNbfValid)
}

func isNbfValid(ctx context.Context, t Token) error {
	if tv := t.NotBefore(); !tv.IsZero() && tv.Unix() != 0 {
		clock := ValidationCtxClock(ctx) // MUST be populated
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

func HasAudience(audience string) Validator {
	return hasAudience(audience)
}

type hasAudience string

func (audience hasAudience) Validate(_ context.Context, t Token) error {
	var found bool
	for _, v := range t.Audience() {
		if v == string(audience) {
			found = true
			break
		}
	}
	if !found {
		return errors.New(`aud not satisfied`)
	}
	return nil
}

type ClaimValue struct {
	name  string
	value interface{}
}

func ClaimValueIs(name string, value interface{}) Validator {
	return &ClaimValue{name: name, value: value}
}

func (cv *ClaimValue) Validate(_ context.Context, t Token) error {
	v, ok := t.Get(cv.name)
	if !ok {
		return errors.Errorf(`%q not satisfied: claim %q does not exist`, cv.name, cv.name)
	}
	if v != cv.value {
		return errors.Errorf(`%q not satisfied: values do not match`, cv.name)
	}
	return nil
}

func IsRequired(name string) Validator {
	return isRequired(name)
}

type isRequired string

func (ir isRequired) Validate(_ context.Context, t Token) error {
	_, ok := t.Get(string(ir))
	if !ok {
		return errors.Errorf(`required claim %q was not found`, string(ir))
	}
	return nil
}
