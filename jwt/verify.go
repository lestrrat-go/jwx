package jwt

import (
	"errors"
	"fmt"
	"time"
)

type VerifyOption func(*verifyOptions)

type verifyOptions struct {
	issuer      string
	subject     string
	audience    string
	jwtid       string
	clock       Clock
	skew        time.Duration
	claimValues map[string]interface{}
}

const (
	optkeyAcceptableSkew = "acceptableSkew"
	optkeyClock          = "clock"
	optkeyIssuer         = "issuer"
	optkeySubject        = "subject"
	optkeyAudience       = "audience"
	optkeyJwtid          = "jwtid"
)

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
	return func(vo *verifyOptions) {
		vo.clock = c
	}
}

// WithAcceptableSkew specifies the duration in which exp and nbf
// claims may differ by. This value should be positive
func WithAcceptableSkew(dur time.Duration) VerifyOption {
	return func(vo *verifyOptions) {
		vo.skew = dur
	}
}

// WithIssuer specifies that expected issuer value. If not specified,
// the value of issuer is not verified at all.
func WithIssuer(s string) VerifyOption {
	return func(vo *verifyOptions) {
		vo.issuer = s
	}
}

// WithSubject specifies that expected subject value. If not specified,
// the value of subject is not verified at all.
func WithSubject(s string) VerifyOption {
	return func(vo *verifyOptions) {
		vo.subject = s
	}
}

// WithJwtID specifies that expected jti value. If not specified,
// the value of jti is not verified at all.
func WithJwtID(s string) VerifyOption {
	return func(vo *verifyOptions) {
		vo.jwtid = s
	}
}

// WithAudience specifies that expected audience value.
// Verify will return true if one of the values in the `aud` element
// matches this value.  If not specified, the value of issuer is not
// verified at all.
func WithAudience(s string) VerifyOption {
	return func(vo *verifyOptions) {
		vo.audience = s
	}
}

// WithClaimValue specifies that expected any claim value.
func WithClaimValue(name string, v interface{}) VerifyOption {
	return func(vo *verifyOptions) {
		if vo.claimValues == nil {
			vo.claimValues = make(map[string]interface{})
		}
		vo.claimValues[name] = v
	}
}

// Verify makes sure that the essential claims stand.
//
// See the various `WithXXX` functions for optional parameters
// that can control the behavior of this method.
func Verify(t Token, options ...VerifyOption) error {
	opts := verifyOptions{
		clock:       ClockFunc(time.Now),
		claimValues: make(map[string]interface{}),
	}
	for _, o := range options {
		o(&opts)
	}

	// check for iss
	if len(opts.issuer) > 0 {
		if v := t.Issuer(); v != "" && v != opts.issuer {
			return errors.New(`iss not satisfied`)
		}
	}

	// check for jti
	if len(opts.jwtid) > 0 {
		if v := t.JwtID(); v != "" && v != opts.jwtid {
			return errors.New(`jti not satisfied`)
		}
	}

	// check for sub
	if len(opts.subject) > 0 {
		if v := t.Subject(); v != "" && v != opts.subject {
			return errors.New(`sub not satisfied`)
		}
	}

	// check for aud
	if len(opts.audience) > 0 {
		var found bool
		for _, v := range t.Audience() {
			if v == opts.audience {
				found = true
				break
			}
		}
		if !found {
			return errors.New(`aud not satisfied`)
		}
	}

	// check for exp
	if tv := t.Expiration(); !tv.IsZero() {
		now := opts.clock.Now().Truncate(time.Second)
		ttv := tv.Truncate(time.Second)
		if !now.Before(ttv.Add(opts.skew)) {
			return errors.New(`exp not satisfied`)
		}
	}

	// check for iat
	if tv := t.IssuedAt(); !tv.IsZero() {
		now := opts.clock.Now().Truncate(time.Second)
		ttv := tv.Truncate(time.Second)
		if now.Before(ttv.Add(-1 * opts.skew)) {
			return errors.New(`iat not satisfied`)
		}
	}

	// check for nbf
	if tv := t.NotBefore(); !tv.IsZero() {
		now := opts.clock.Now().Truncate(time.Second)
		ttv := tv.Truncate(time.Second)
		// now cannot be before t, so we check for now > t - skew
		if !now.After(ttv.Add(-1 * opts.skew)) {
			return errors.New(`nbf not satisfied`)
		}
	}

	for name, expectedValue := range opts.claimValues {
		if v, ok := t.Get(name); !ok || v != expectedValue {
			return fmt.Errorf(`%v not satisfied`, name)
		}
	}

	return nil
}
