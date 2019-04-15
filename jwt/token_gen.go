package jwt

import (
	"encoding/json"
	"github.com/pkg/errors"
	"time"
)

// Key names for standard claims
const (
	AudienceKey   = "aud"
	ExpirationKey = "exp"
	IssuedAtKey   = "iat"
	IssuerKey     = "iss"
	JwtIDKey      = "jti"
	NotBeforeKey  = "nbf"
	SubjectKey    = "sub"
)

// Token represents a JWT token. The object has convenience accessors
// to 7 standard claims including "aud", "exp", "iat", "iss", "jti", "nbf", and "sub"
// which are type-aware (to an extent). Other claims may be accessed via the `Get`/`Set`
// methods but their types are not taken into consideration at all. If you have non-standard
// claims that you must frequently access, consider wrapping the token in a wrapper
// by embedding the jwt.Token type in it
type Token struct {
	audience      stringList   // https://tools.ietf.org/html/rfc7519#section-4.1.3
	expiration    *NumericDate // https://tools.ietf.org/html/rfc7519#section-4.1.4
	issuedAt      *NumericDate // https://tools.ietf.org/html/rfc7519#section-4.1.6
	issuer        *string      // https://tools.ietf.org/html/rfc7519#section-4.1.1
	jwtID         *string      // https://tools.ietf.org/html/rfc7519#section-4.1.7
	notBefore     *NumericDate // https://tools.ietf.org/html/rfc7519#section-4.1.5
	subject       *string      // https://tools.ietf.org/html/rfc7519#section-4.1.2
	privateClaims map[string]interface{}
}

func (t *Token) Get(s string) (interface{}, bool) {
	switch s {
	case AudienceKey:
		if len(t.audience) == 0 {
			return nil, false
		}
		return []string(t.audience), true
	case ExpirationKey:
		if t.expiration == nil {
			return nil, false
		} else {
			return t.expiration.Get(), true
		}
	case IssuedAtKey:
		if t.issuedAt == nil {
			return nil, false
		} else {
			return t.issuedAt.Get(), true
		}
	case IssuerKey:
		if t.issuer == nil {
			return nil, false
		} else {
			return *(t.issuer), true
		}
	case JwtIDKey:
		if t.jwtID == nil {
			return nil, false
		} else {
			return *(t.jwtID), true
		}
	case NotBeforeKey:
		if t.notBefore == nil {
			return nil, false
		} else {
			return t.notBefore.Get(), true
		}
	case SubjectKey:
		if t.subject == nil {
			return nil, false
		} else {
			return *(t.subject), true
		}
	}
	if v, ok := t.privateClaims[s]; ok {
		return v, true
	}
	return nil, false
}

func (t *Token) Set(name string, v interface{}) error {
	switch name {
	case AudienceKey:
		var x stringList
		if err := x.Accept(v); err != nil {
			return errors.Wrap(err, `invalid value for 'audience' key`)
		}
		t.audience = x
	case ExpirationKey:
		var x NumericDate
		if err := x.Accept(v); err != nil {
			return errors.Wrap(err, `invalid value for 'expiration' key`)
		}
		t.expiration = &x
	case IssuedAtKey:
		var x NumericDate
		if err := x.Accept(v); err != nil {
			return errors.Wrap(err, `invalid value for 'issuedAt' key`)
		}
		t.issuedAt = &x
	case IssuerKey:
		x, ok := v.(string)
		if !ok {
			return errors.Errorf(`invalid type for 'issuer' key: %T`, v)
		}
		t.issuer = &x
	case JwtIDKey:
		x, ok := v.(string)
		if !ok {
			return errors.Errorf(`invalid type for 'jwtID' key: %T`, v)
		}
		t.jwtID = &x
	case NotBeforeKey:
		var x NumericDate
		if err := x.Accept(v); err != nil {
			return errors.Wrap(err, `invalid value for 'notBefore' key`)
		}
		t.notBefore = &x
	case SubjectKey:
		x, ok := v.(string)
		if !ok {
			return errors.Errorf(`invalid type for 'subject' key: %T`, v)
		}
		t.subject = &x
	default:
		t.privateClaims[name] = v
	}
	return nil
}

func (t *Token) UnmarshalJSON(data []byte) error {
	m := make(map[string]interface{})
	if err := json.Unmarshal(data, &m); err != nil {
		return errors.Wrap(err, `failed to unmarshal claims`)
	}
	t.privateClaims = make(map[string]interface{})
	for k, v := range m {
		if err := t.Set(k, v); err != nil {
			return errors.Wrapf(err, `failed to set key '%s'`, k)
		}
	}
	return nil
}

func (t Token) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})
	for k, v := range t.privateClaims {
		m[k] = v
	}

	if l := len(t.audience); l > 0 {
		switch l {
		case 0:
		// no op
		case 1:
			m[AudienceKey] = t.audience[0]
		default:
			m[AudienceKey] = t.audience
		}
	}

	if v := t.expiration; v != nil {
		m[ExpirationKey] = *v
	}

	if v := t.issuedAt; v != nil {
		m[IssuedAtKey] = *v
	}

	if v := t.issuer; v != nil {
		m[IssuerKey] = *v
	}

	if v := t.jwtID; v != nil {
		m[JwtIDKey] = *v
	}

	if v := t.notBefore; v != nil {
		m[NotBeforeKey] = *v
	}

	if v := t.subject; v != nil {
		m[SubjectKey] = *v
	}

	return json.Marshal(m)
}

func (t Token) Audience() string {
	if v, ok := t.Get(AudienceKey); ok {
		return (v.([]string))[0]
	}
	return ""
}

func (t Token) Expiration() time.Time {
	if v, ok := t.Get(ExpirationKey); ok {
		return v.(time.Time)
	}
	return time.Time{}
}

func (t Token) IssuedAt() time.Time {
	if v, ok := t.Get(IssuedAtKey); ok {
		return v.(time.Time)
	}
	return time.Time{}
}

// Issuer is a convenience function to retrieve the corresponding value store in the token
// if there is a problem retrieving the value, the zero value is returned. If you need to differentiate between existing/non-existing values, use `Get` instead
func (t Token) Issuer() string {
	if v, ok := t.Get(IssuerKey); ok {
		return v.(string)
	}
	return ""
}

// JwtID is a convenience function to retrieve the corresponding value store in the token
// if there is a problem retrieving the value, the zero value is returned. If you need to differentiate between existing/non-existing values, use `Get` instead
func (t Token) JwtID() string {
	if v, ok := t.Get(JwtIDKey); ok {
		return v.(string)
	}
	return ""
}

func (t Token) NotBefore() time.Time {
	if v, ok := t.Get(NotBeforeKey); ok {
		return v.(time.Time)
	}
	return time.Time{}
}

// Subject is a convenience function to retrieve the corresponding value store in the token
// if there is a problem retrieving the value, the zero value is returned. If you need to differentiate between existing/non-existing values, use `Get` instead
func (t Token) Subject() string {
	if v, ok := t.Get(SubjectKey); ok {
		return v.(string)
	}
	return ""
}
