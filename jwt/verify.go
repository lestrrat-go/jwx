package jwt

import (
	"errors"
	"time"
)

const (
	acceptableSkewKey = "acceptableSkew"
	clockKey          = "clock"
	issuerKey         = "issuer"
)

type VerifyOption interface {
	Name() string
	Value() interface{}
}

type verifyOption struct {
	name  string
	value interface{}
}

func (o *verifyOption) Name() string {
	return o.name
}

func (o *verifyOption) Value() interface{} {
	return o.value
}

type Clock interface {
	Now() time.Time
}
type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time {
	return f()
}

// WithClock specifies the `Clock` to be used when verifying
// claims exp and nbf.
func WithClock(c Clock) VerifyOption {
	return &verifyOption{
		name:  clockKey,
		value: c,
	}
}

// WithAcceptableSkew specifies the duration in which exp and nbf
// claims may differ by. This value should be positive
func WithAcceptableSkew(dur time.Duration) VerifyOption {
	return &verifyOption{
		name:  acceptableSkewKey,
		value: dur,
	}
}

// WithIssuer specifies that expected issuer value. If not specified,
// the value of issuer is not verified at all.
func WithIssuer(s string) VerifyOption {
	return &verifyOption{
		name:  issuerKey,
		value: s,
	}
}

// Verify makes sure that the essential claims stand.
//
// See the various `WithXXX` functions for optional parameters
// that can control the behavior of this method.
func (c *ClaimSet) Verify(options ...VerifyOption) error {
	var issuer string
	var clock Clock = ClockFunc(time.Now)
	var skew time.Duration
	for _, o := range options {
		switch o.Name() {
		case clockKey:
			clock = o.Value().(Clock)
		case acceptableSkewKey:
			skew = o.Value().(time.Duration)
		case issuerKey:
			issuer = o.Value().(string)
		}
	}

	// check for iss
	if len(issuer) > 0 {
		if c.Issuer != issuer {
			return errors.New(`issuer not satisfied`)
		}
	}

	// sub
	// aud
	// check for exp
	if tv := c.Expiration; tv > 0 {
		t := time.Unix(tv, 0)
		now := clock.Now().Truncate(time.Second)
		if !now.Before(t.Add(skew)) {
			return errors.New(`exp not satisfied`)
		}
	}

	// iat
	// jti
	// check for nbf
	if t := c.NotBefore; t != nil {
		now := clock.Now().Truncate(time.Second)
		// now cannot be before t, so we check for now > t - skew
		if !now.After(t.Time.Add(-1 * skew).Truncate(time.Second)) {
			return errors.New(`nbf not satisfied`)
		}
	}
	return nil
}
