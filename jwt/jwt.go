// Package jwt implements JSON Web Tokens as described in https://tools.ietf.org/html/rfc7519
package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat/go-jwx/internal/emap"
)

func (n NumericDate) MarshalJSON() ([]byte, error) {
	return json.Marshal(n.UTC().Format(numericDateFmt))
}

func (n *NumericDate) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	t, err := time.Parse(numericDateFmt, s)
	if err != nil {
		return err
	}

	*n = NumericDate{t}
	return nil
}

func NewClaimSet() *ClaimSet {
	return &ClaimSet{
		EssentialClaims: &EssentialClaims{},
		PrivateClaims:   map[string]interface{}{},
	}
}

func (c *ClaimSet) MarshalJSON() ([]byte, error) {
	// Reverting time back for machines whose time is not perfectly in sync.
	// If client machine's time is in the future according
	// to Google servers, an access token will not be issued.
	now := time.Now().Add(-10 * time.Second)
	if c.IssuedAt == 0 {
		c.IssuedAt = now.Unix()
	}
	if c.Expiration == 0 {
		c.Expiration = now.Add(time.Hour).Unix()
	}
	if c.Expiration < c.IssuedAt {
		return nil, fmt.Errorf("invalid expiration = %v; must be later than issued_at = %v", c.Expiration, c.IssuedAt)
	}

	return emap.MergeMarshal(c.EssentialClaims, c.PrivateClaims)
}

func (c *ClaimSet) UnmarshalJSON(data []byte) error {
	if c.EssentialClaims == nil {
		c.EssentialClaims = &EssentialClaims{}
	}
	if c.PrivateClaims == nil {
		c.PrivateClaims = map[string]interface{}{}
	}
	return emap.MergeUnmarshal(data, c.EssentialClaims, &c.PrivateClaims)
}

func (c *EssentialClaims) Construct(m map[string]interface{}) error {
	r := emap.Hmap(m)
	c.Audience, _ = r.GetString("aud")
	c.Expiration, _ = r.GetInt64("exp")
	c.IssuedAt, _ = r.GetInt64("iat")
	c.Issuer, _ = r.GetString("iss")
	c.JwtID, _ = r.GetString("jti")
	if v, err := r.GetString("nbf"); err != nil {
		if v != "" {
			t, err := time.Parse(numericDateFmt, v)
			if err != nil {
				return err
			}
			c.NotBefore = &NumericDate{t}
		}
	}
	c.Subject, _ = r.GetString("sub")
	return nil
}

var ErrInvalidValue = errors.New("invalid value for key")

// Set takes a key and a value, and sets the appropriate values in the
// `ClaimSet` for you. If the key is a known ("Essential") claim, it is set
// in `c.EssentialClaim` struct, which means that some amoutn of type safety
// is asserted. Otherwise it is assumed to be a private claim as is.
//
// Set returns an error if a known essential claim name is used and its type
// does not match with the type given in `value`.
// If you want to rely on compile time check for types, you should be
// assigning values directly to the struct.
func (c *ClaimSet) Set(key string, value interface{}) error {
	switch key {
	case "aud":
		v, ok := value.(string)
		if !ok {
			return ErrInvalidValue
		}
		c.Audience = v
	case "exp":
		v, ok := value.(int64)
		if !ok {
			return ErrInvalidValue
		}
		c.Expiration = v
	case "iat":
		v, ok := value.(int64)
		if !ok {
			return ErrInvalidValue
		}
		c.IssuedAt = v
	case "iss":
		v, ok := value.(string)
		if !ok {
			return ErrInvalidValue
		}
		c.Issuer = v
	case "jti":
		v, ok := value.(string)
		if !ok {
			return ErrInvalidValue
		}
		c.JwtID = v
	case "nbf":
		switch value.(type) {
		case NumericDate:
			v := value.(NumericDate)
			c.NotBefore = &NumericDate{v.Time}
		case *NumericDate:
			c.NotBefore = value.(*NumericDate)
		case time.Time:
			c.NotBefore = &NumericDate{value.(time.Time)}
		default:
			return ErrInvalidValue
		}
	case "sub":
		v, ok := value.(string)
		if !ok {
			return ErrInvalidValue
		}
		c.Subject = v
	default:
		c.PrivateClaims[key] = value
	}

	return nil
}
