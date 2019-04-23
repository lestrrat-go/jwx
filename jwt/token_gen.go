// This file is auto-generated. DO NOT EDIT
package jwt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/pkg/errors"
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
// to 7 standard claims including "aud", "exp", "iat", "iss", "jti", "nbf" and "sub"
// which are type-aware (to an extent). Other claims may be accessed via the `Get`/`Set`
// methods but their types are not taken into consideration at all. If you have non-standard
// claims that you must frequently access, consider wrapping the token in a wrapper
// by embedding the jwt.Token type in it
type Token struct {
	Audience      StringList   // https://tools.ietf.org/html/rfc7519#section-4.1.3
	Expiration    *NumericDate // https://tools.ietf.org/html/rfc7519#section-4.1.4
	IssuedAt      *NumericDate // https://tools.ietf.org/html/rfc7519#section-4.1.6
	Issuer        *string      // https://tools.ietf.org/html/rfc7519#section-4.1.1
	JwtID         *string      // https://tools.ietf.org/html/rfc7519#section-4.1.7
	NotBefore     *NumericDate // https://tools.ietf.org/html/rfc7519#section-4.1.5
	Subject       *string      // https://tools.ietf.org/html/rfc7519#section-4.1.2
	privateClaims map[string]interface{}
}

func (t *Token) Get(s string) (interface{}, bool) {
	switch s {
	case AudienceKey:
		if len(t.Audience) == 0 {
			return nil, false
		}
		return []string(t.Audience), true
	case ExpirationKey:
		if t.Expiration == nil {
			return nil, false
		} else {
			return t.Expiration.Get(), true
		}
	case IssuedAtKey:
		if t.IssuedAt == nil {
			return nil, false
		} else {
			return t.IssuedAt.Get(), true
		}
	case IssuerKey:
		if t.Issuer == nil {
			return nil, false
		} else {
			return *(t.Issuer), true
		}
	case JwtIDKey:
		if t.JwtID == nil {
			return nil, false
		} else {
			return *(t.JwtID), true
		}
	case NotBeforeKey:
		if t.NotBefore == nil {
			return nil, false
		} else {
			return t.NotBefore.Get(), true
		}
	case SubjectKey:
		if t.Subject == nil {
			return nil, false
		} else {
			return *(t.Subject), true
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
		var x StringList
		if err := x.Accept(v); err != nil {
			return errors.Wrap(err, `invalid value for 'Audience' key`)
		}
		t.Audience = x
	case ExpirationKey:
		var x NumericDate
		if err := x.Accept(v); err != nil {
			return errors.Wrap(err, `invalid value for 'Expiration' key`)
		}
		t.Expiration = &x
	case IssuedAtKey:
		var x NumericDate
		if err := x.Accept(v); err != nil {
			return errors.Wrap(err, `invalid value for 'IssuedAt' key`)
		}
		t.IssuedAt = &x
	case IssuerKey:
		x, ok := v.(string)
		if !ok {
			return errors.Errorf(`invalid type for 'Issuer' key: %T`, v)
		}
		t.Issuer = &x
	case JwtIDKey:
		x, ok := v.(string)
		if !ok {
			return errors.Errorf(`invalid type for 'JwtID' key: %T`, v)
		}
		t.JwtID = &x
	case NotBeforeKey:
		var x NumericDate
		if err := x.Accept(v); err != nil {
			return errors.Wrap(err, `invalid value for 'NotBefore' key`)
		}
		t.NotBefore = &x
	case SubjectKey:
		x, ok := v.(string)
		if !ok {
			return errors.Errorf(`invalid type for 'Subject' key: %T`, v)
		}
		t.Subject = &x
	default:
		if t.privateClaims == nil {
			t.privateClaims = make(map[string]interface{})
		}
		t.privateClaims[name] = v
	}
	return nil
}

func (t Token) GetAudience() StringList {
	if v, ok := t.Get(AudienceKey); ok {
		return v.([]string)
	}
	return nil
}

func (t Token) GetExpiration() time.Time {
	if v, ok := t.Get(ExpirationKey); ok {
		return v.(time.Time)
	}
	return time.Time{}
}

func (t Token) GetIssuedAt() time.Time {
	if v, ok := t.Get(IssuedAtKey); ok {
		return v.(time.Time)
	}
	return time.Time{}
}

// Issuer is a convenience function to retrieve the corresponding value store in the token
// if there is a problem retrieving the value, the zero value is returned. If you need to differentiate between existing/non-existing values, use `Get` instead

func (t Token) GetIssuer() string {
	if v, ok := t.Get(IssuerKey); ok {
		return v.(string)
	}
	return ""
}

// JwtID is a convenience function to retrieve the corresponding value store in the token
// if there is a problem retrieving the value, the zero value is returned. If you need to differentiate between existing/non-existing values, use `Get` instead

func (t Token) GetJwtID() string {
	if v, ok := t.Get(JwtIDKey); ok {
		return v.(string)
	}
	return ""
}

func (t Token) GetNotBefore() time.Time {
	if v, ok := t.Get(NotBeforeKey); ok {
		return v.(time.Time)
	}
	return time.Time{}
}

// Subject is a convenience function to retrieve the corresponding value store in the token
// if there is a problem retrieving the value, the zero value is returned. If you need to differentiate between existing/non-existing values, use `Get` instead

func (t Token) GetSubject() string {
	if v, ok := t.Get(SubjectKey); ok {
		return v.(string)
	}
	return ""
}

func (x *Token) UnmarshalJSON(b []byte) error {
	var v map[string]json.RawMessage
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}

	var t Token
	for key, value := range v {
		if bytes.Equal(value, []byte("null")) {
			continue
		}
		switch key {
		case AudienceKey:
			fmt.Printf("%s, %q", key, value)
			if err := json.Unmarshal(value, &t.Audience); err != nil {
				return err
			}
		case ExpirationKey:
			if err := json.Unmarshal(value, &t.Expiration); err != nil {
				return err
			}
		case IssuedAtKey:
			if err := json.Unmarshal(value, &t.IssuedAt); err != nil {
				return err
			}
		case IssuerKey:
			if err := json.Unmarshal(value, &t.Issuer); err != nil {
				return err
			}
		case JwtIDKey:
			if err := json.Unmarshal(value, &t.JwtID); err != nil {
				return err
			}
		case NotBeforeKey:
			if err := json.Unmarshal(value, &t.NotBefore); err != nil {
				return err
			}
		case SubjectKey:
			if err := json.Unmarshal(value, &t.Subject); err != nil {
				return err
			}
		default:
			var v interface{}
			if err := json.Unmarshal(value, &v); err != nil {
				return err
			}
			if t.privateClaims == nil {
				t.privateClaims = make(map[string]interface{})
			}
			t.privateClaims[key] = v
		}
	}
	*x = t
	return nil
}

func (t Token) MarshalJSON() ([]byte, error) {
	v := make(map[string]json.RawMessage)
	var err error

	if t.Audience != nil {
		v[AudienceKey], err = json.Marshal(&t.Audience)
		if err != nil {
			return nil, err
		}
	}
	if t.Expiration != nil {
		v[ExpirationKey], err = json.Marshal(&t.Expiration)
		if err != nil {
			return nil, err
		}
	}
	if t.IssuedAt != nil {
		v[IssuedAtKey], err = json.Marshal(&t.IssuedAt)
		if err != nil {
			return nil, err
		}
	}
	if t.Issuer != nil {
		v[IssuerKey], err = json.Marshal(&t.Issuer)
		if err != nil {
			return nil, err
		}
	}
	if t.JwtID != nil {
		v[JwtIDKey], err = json.Marshal(&t.JwtID)
		if err != nil {
			return nil, err
		}
	}
	if t.NotBefore != nil {
		v[NotBeforeKey], err = json.Marshal(&t.NotBefore)
		if err != nil {
			return nil, err
		}
	}
	if t.Subject != nil {
		v[SubjectKey], err = json.Marshal(&t.Subject)
		if err != nil {
			return nil, err
		}
	}

	for key, value := range t.privateClaims {
		if value != nil {
			v[key], err = json.Marshal(&value)
			if err != nil {
				return nil, err
			}
		}
	}

	return json.Marshal(v)
}
