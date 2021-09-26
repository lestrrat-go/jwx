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
	ctx := context.Background()
	var clock Clock = ClockFunc(time.Now)
	var skew time.Duration
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
		case identContext{}:
			ctx = o.Value().(context.Context)
		case identValidator{}:
			v := o.Value().(Validator)
			switch v := v.(type) {
			case *isInTimeRange:
				if v.c1 != "" {
					if err := isSupportedTimeClaim(v.c1); err != nil {
						return err
					}
					validators = append(validators, IsRequired(v.c1))
				}
				if v.c2 != "" {
					if err := isSupportedTimeClaim(v.c2); err != nil {
						return err
					}
					validators = append(validators, IsRequired(v.c2))
				}
			}
			validators = append(validators, v)
		}
	}

	ctx = SetValidationCtxSkew(ctx, skew)
	ctx = SetValidationCtxClock(ctx, clock)
	for _, v := range validators {
		if err := v.Validate(ctx, t); err != nil {
			return err
		}
	}

	return nil
}

type isInTimeRange struct {
	c1   string
	c2   string
	dur  time.Duration
	less bool // if true, d =< c1 - c2. otherwise d >= c1 - c2
}

// MaxDeltaIs implements the logic behind `WithMaxDelta()` option
func MaxDeltaIs(c1, c2 string, dur time.Duration) Validator {
	return &isInTimeRange{
		c1:   c1,
		c2:   c2,
		dur:  dur,
		less: true,
	}
}

// MinDeltaIs implements the logic behind `WithMinDelta()` option
func MinDeltaIs(c1, c2 string, dur time.Duration) Validator {
	return &isInTimeRange{
		c1:   c1,
		c2:   c2,
		dur:  dur,
		less: false,
	}
}

func (iitr *isInTimeRange) Validate(ctx context.Context, t Token) error {
	clock := ValidationCtxClock(ctx) // MUST be populated
	skew := ValidationCtxSkew(ctx)   // MUST be populated
	// We don't check if the claims already exist, because we already did that
	// by piggybacking on `required` check.
	t1 := timeClaim(t, clock, iitr.c1).Truncate(time.Second)
	t2 := timeClaim(t, clock, iitr.c2).Truncate(time.Second)
	if iitr.less { // t1 - t2 <= iitr.dur
		// t1 - t2 < iitr.dur + skew
		if t1.Sub(t2) > iitr.dur+skew {
			return errors.Errorf(`iitr between %s and %s exceeds %s (skew %s)`, iitr.c1, iitr.c2, iitr.dur, skew)
		}
	} else {
		if t1.Sub(t2) < iitr.dur-skew {
			return errors.Errorf(`iitr between %s and %s is less than %s (skew %s)`, iitr.c1, iitr.c2, iitr.dur, skew)
		}
	}
	return nil
}

// Validator describes interface to validate a Token.
type Validator interface {
	Validate(context.Context, Token) error
}

// ValidatorFunc is a type of Validator that does not have any
// state, that is implemented as a function
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

// IsExpirationValid is one of the default validators that will be executed.
// It does not need to be specified by users, but it exists as an
// exported field so that you can check what it does.
//
// The supplied context.Context object must have the "clock" and "skew"
// populated with appropriate values using SetValidationCtxClock() and
// SetValidationCtxSkew()
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

// IsIssuedAtValid is one of the default validators that will be executed.
// It does not need to be specified by users, but it exists as an
// exported field so that you can check what it does.
//
// The supplied context.Context object must have the "clock" and "skew"
// populated with appropriate values using SetValidationCtxClock() and
// SetValidationCtxSkew()
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

type claimContainsString struct {
	name  string
	value string
}

// ClaimContainsString can be used to check if the claim called `name`, which is
// expected to be a list of strings, contains `value`. Currently because of the
// implementation this will probably only work for `aud` fields.
func ClaimContainsString(name, value string) Validator {
	return claimContainsString{
		name:  name,
		value: value,
	}
}

func (ccs claimContainsString) Validate(_ context.Context, t Token) error {
	v, ok := t.Get(ccs.name)
	if !ok {
		return errors.Errorf(`claim %q not found`, ccs.name)
	}

	list, ok := v.([]string)
	if !ok {
		return errors.Errorf(`claim %q must be a []string (got %T)`, ccs.name, v)
	}

	var found bool
	for _, v := range list {
		if v == ccs.value {
			found = true
			break
		}
	}
	if !found {
		return errors.Errorf(`%s not satisfied`, ccs.name)
	}
	return nil
}

type claimValueIs struct {
	name  string
	value interface{}
}

// ClaimValueIs creates a Validator that checks if the value of claim `name`
// matches `value`. The comparison is done using a simple `==` comparison,
// and therefore complex comparisons may fail using this code. If you
// need to do more, use a custom Validator.
func ClaimValueIs(name string, value interface{}) Validator {
	return &claimValueIs{name: name, value: value}
}

func (cv *claimValueIs) Validate(_ context.Context, t Token) error {
	v, ok := t.Get(cv.name)
	if !ok {
		return errors.Errorf(`%q not satisfied: claim %q does not exist`, cv.name, cv.name)
	}
	if v != cv.value {
		return errors.Errorf(`%q not satisfied: values do not match`, cv.name)
	}
	return nil
}

// IsRequired creates a Validator that checks if the required claim `name`
// exists in the token
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
