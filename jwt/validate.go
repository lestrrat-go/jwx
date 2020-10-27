package jwt

import (
	"errors"
	"fmt"
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

type Clock interface {
	Now() time.Time
}
type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time {
	return f()
}

// Verify has been deprecated in favor of `Validate` function,
// to avoid confusion between verifying the JWS signature during `Parse`,
// and the validation of the JWT token's contents
func Verify(t Token, options ...ValidateOption) error {
	return Validate(t, options...)
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
	claimValues := make(map[string]interface{})
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
		case optkeyClaim:
			claim := o.Value().(claimValue)
			claimValues[claim.name] = claim.value
		}
	}

	// check for iss
	if len(issuer) > 0 {
		if v := t.Issuer(); v != "" && v != issuer {
			return errors.New(`iss not satisfied`)
		}
	}

	// check for jti
	if len(jwtid) > 0 {
		if v := t.JwtID(); v != "" && v != jwtid {
			return errors.New(`jti not satisfied`)
		}
	}

	// check for sub
	if len(subject) > 0 {
		if v := t.Subject(); v != "" && v != subject {
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
	if tv := t.Expiration(); !tv.IsZero() {
		now := clock.Now().Truncate(time.Second)
		ttv := tv.Truncate(time.Second)
		if !now.Before(ttv.Add(skew)) {
			return errors.New(`exp not satisfied`)
		}
	}

	// check for iat
	if tv := t.IssuedAt(); !tv.IsZero() {
		now := clock.Now().Truncate(time.Second)
		ttv := tv.Truncate(time.Second)
		if now.Before(ttv.Add(-1 * skew)) {
			return errors.New(`iat not satisfied`)
		}
	}

	// check for nbf
	if tv := t.NotBefore(); !tv.IsZero() {
		now := clock.Now().Truncate(time.Second)
		ttv := tv.Truncate(time.Second)
		// now cannot be before t, so we check for now > t - skew
		if !now.After(ttv.Add(-1 * skew)) {
			return errors.New(`nbf not satisfied`)
		}
	}

	for name, expectedValue := range claimValues {
		if v, ok := t.Get(name); !ok || v != expectedValue {
			return fmt.Errorf(`%v not satisfied`, name)
		}
	}

	return nil
}
