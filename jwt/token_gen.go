// This file is auto-generated. DO NOT EDIT
package jwt

import (
	"bytes"
	"encoding/json"
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
	Audience      StringList             `json:"aud,omitempty"` // https://tools.ietf.org/html/rfc7519#section-4.1.3
	Expiration    *NumericDate           `json:"exp,omitempty"` // https://tools.ietf.org/html/rfc7519#section-4.1.4
	IssuedAt      *NumericDate           `json:"iat,omitempty"` // https://tools.ietf.org/html/rfc7519#section-4.1.6
	Issuer        *string                `json:"iss,omitempty"` // https://tools.ietf.org/html/rfc7519#section-4.1.1
	JwtID         *string                `json:"jti,omitempty"` // https://tools.ietf.org/html/rfc7519#section-4.1.7
	NotBefore     *NumericDate           `json:"nbf,omitempty"` // https://tools.ietf.org/html/rfc7519#section-4.1.5
	Subject       *string                `json:"sub,omitempty"` // https://tools.ietf.org/html/rfc7519#section-4.1.2
	PrivateClaims map[string]interface{} `json:"-"`
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
	if v, ok := t.PrivateClaims[s]; ok {
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
		if t.PrivateClaims == nil {
			t.PrivateClaims = make(map[string]interface{})
		}
		t.PrivateClaims[name] = v
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

// this is almost identical to json.Encoder.Encode(), but we use Marshal
// to avoid having to remove the trailing newline for each successive
// call to Encode()
func writeJSON(buf *bytes.Buffer, v interface{}, keyName string) error {
	if enc, err := json.Marshal(v); err != nil {
		return errors.Wrapf(err, `failed to encode '%s'`, keyName)
	} else {
		buf.Write(enc)
	}
	return nil
}

// MarshalJSON serializes the token in JSON format. This exists to
// allow flattening of private claims.
func (t Token) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteRune('{')
	if len(t.Audience) > 0 {
		buf.WriteRune('"')
		buf.WriteString(AudienceKey)
		buf.WriteString(`":`)
		if err := writeJSON(&buf, t.Audience, AudienceKey); err != nil {
			return nil, err
		}
	}
	if t.Expiration != nil {
		if buf.Len() > 1 {
			buf.WriteRune(',')
		}
		buf.WriteRune('"')
		buf.WriteString(ExpirationKey)
		buf.WriteString(`":`)
		if err := writeJSON(&buf, t.Expiration, ExpirationKey); err != nil {
			return nil, err
		}
	}
	if t.IssuedAt != nil {
		if buf.Len() > 1 {
			buf.WriteRune(',')
		}
		buf.WriteRune('"')
		buf.WriteString(IssuedAtKey)
		buf.WriteString(`":`)
		if err := writeJSON(&buf, t.IssuedAt, IssuedAtKey); err != nil {
			return nil, err
		}
	}
	if t.Issuer != nil {
		if buf.Len() > 1 {
			buf.WriteRune(',')
		}
		buf.WriteRune('"')
		buf.WriteString(IssuerKey)
		buf.WriteString(`":`)
		if err := writeJSON(&buf, t.Issuer, IssuerKey); err != nil {
			return nil, err
		}
	}
	if t.JwtID != nil {
		if buf.Len() > 1 {
			buf.WriteRune(',')
		}
		buf.WriteRune('"')
		buf.WriteString(JwtIDKey)
		buf.WriteString(`":`)
		if err := writeJSON(&buf, t.JwtID, JwtIDKey); err != nil {
			return nil, err
		}
	}
	if t.NotBefore != nil {
		if buf.Len() > 1 {
			buf.WriteRune(',')
		}
		buf.WriteRune('"')
		buf.WriteString(NotBeforeKey)
		buf.WriteString(`":`)
		if err := writeJSON(&buf, t.NotBefore, NotBeforeKey); err != nil {
			return nil, err
		}
	}
	if t.Subject != nil {
		if buf.Len() > 1 {
			buf.WriteRune(',')
		}
		buf.WriteRune('"')
		buf.WriteString(SubjectKey)
		buf.WriteString(`":`)
		if err := writeJSON(&buf, t.Subject, SubjectKey); err != nil {
			return nil, err
		}
	}
	if len(t.PrivateClaims) == 0 {
		buf.WriteRune('}')
		return buf.Bytes(), nil
	}
	// If private claims exist, they need to flattened and included in the token
	pcjson, err := json.Marshal(t.PrivateClaims)
	if err != nil {
		return nil, errors.Wrap(err, `failed to marshal private claims`)
	}
	// remove '{' from the private claims
	pcjson = pcjson[1:]
	if buf.Len() > 1 {
		buf.WriteRune(',')
	}
	buf.Write(pcjson)
	return buf.Bytes(), nil
}

func (t *Token) UnmarshalJSON(data []byte) error {
	var m map[string]interface{}

	if err := json.Unmarshal(data, &m); err != nil {
		return errors.Wrap(err, `failed to unmarshal token`)
	}

	for name, value := range m {
		if err := t.Set(name, value); err != nil {
			return errors.Wrapf(err, `failed to set value for %s`, name)
		}
	}
	return nil
}
