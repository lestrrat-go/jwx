package jwt

import (
	"errors"
	"time"
)

const (
	optkeyAcceptableSkew = "acceptableSkew"
	optkeyClock          = "clock"
	optkeyIssuer         = "issuer"
	optkeySubject        = "subject"
	optkeyAudience       = "audience"
	optkeyJwtid          = "jwtid"
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
		name:  optkeyClock,
		value: c,
	}
}

// WithAcceptableSkew specifies the duration in which exp and nbf
// claims may differ by. This value should be positive
func WithAcceptableSkew(dur time.Duration) VerifyOption {
	return &verifyOption{
		name:  optkeyAcceptableSkew,
		value: dur,
	}
}

// WithIssuer specifies that expected issuer value. If not specified,
// the value of issuer is not verified at all.
func WithIssuer(s string) VerifyOption {
	return &verifyOption{
		name:  optkeyIssuer,
		value: s,
	}
}

// WithSubject specifies that expected subject value. If not specified,
// the value of subject is not verified at all.
func WithSubject(s string) VerifyOption {
	return &verifyOption{
		name:  optkeySubject,
		value: s,
	}
}

// WithJwtID specifies that expected jti value. If not specified,
// the value of jti is not verified at all.
func WithJwtID(s string) VerifyOption {
	return &verifyOption{
		name:  optkeyJwtid,
		value: s,
	}
}

// WithAudience specifies that expected audience value.
// Verify will return true if one of the values in the `aud` element
// matches this value.  If not specified, the value of issuer is not
// verified at all.
func WithAudience(s string) VerifyOption {
	return &verifyOption{
		name:  optkeyAudience,
		value: s,
	}
}

// Verify makes sure that the essential claims stand.
//
// See the various `WithXXX` functions for optional parameters
// that can control the behavior of this method.
func (t *Token) Verify(options ...VerifyOption) error {
	var issuer string
	var subject string
	var audience string
	var jwtid string
	var clock Clock = ClockFunc(time.Now)
	var skew time.Duration
	for _, o := range options {
		switch o.Name() {
		case optkeyClock:
			clock = o.Value().(Clock)
		case optkeyAcceptableSkew:
			skew = o.Value().(time.Duration)
		case optkeyIssuer:
			issuer = o.Value().(string)
		case optkeySubject:
			subject = o.Value().(string)
		case optkeyAudience:
			audience = o.Value().(string)
		case optkeyJwtid:
			jwtid = o.Value().(string)
		}
	}

	// check for iss
	if len(issuer) > 0 {
		if v := t.issuer; v != nil && *v != issuer {
			return errors.New(`iss not satisfied`)
		}
	}

	// check for jti
	if len(jwtid) > 0 {
		if v := t.jwtID; v != nil && *v != jwtid {
			return errors.New(`jti not satisfied`)
		}
	}

	// check for sub
	if len(subject) > 0 {
		if v := t.subject; v != nil && *v != subject {
			return errors.New(`sub not satisfied`)
		}
	}

	// check for aud
	if len(audience) > 0 {
		var found bool
		for _, v := range t.audience {
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
	if tv := t.expiration; tv != nil {
		now := clock.Now().Truncate(time.Second)
		if !now.Before(tv.Add(skew)) {
			return errors.New(`exp not satisfied`)
		}
	}

	// check for iat
	if tv := t.issuedAt; tv != nil {
		now := clock.Now().Truncate(time.Second)
		if !now.After(tv.Add(-1 * skew)) {
			return errors.New(`iat not satisfied`)
		}
	}

	// jti
	// check for nbf
	if t := t.notBefore; t != nil {
		now := clock.Now().Truncate(time.Second)
		// now cannot be before t, so we check for now > t - skew
		if !now.After(t.Time.Add(-1 * skew).Truncate(time.Second)) {
			return errors.New(`nbf not satisfied`)
		}
	}
	return nil
}
