package jwt

import (
	"bytes"
	"encoding/json"
	"fmt"
)

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
