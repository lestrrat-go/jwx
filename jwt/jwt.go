// Package jwt implements JSON Web Tokens as described in https://tools.ietf.org/html/rfc7519
package jwt

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat/go-jwx/internal/emap"
	"github.com/pkg/errors"
)

// MarshalJSON generates JSON representation of this instant
func (n NumericDate) MarshalJSON() ([]byte, error) {
	return json.Marshal(n.UTC().Format(numericDateFmt))
}

// UnmarshalJSON parses the JSON representation and initializes this NumericDate
func (n *NumericDate) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return errors.Wrap(err, `failed to decode jwt.NumericDate`)
	}

	t, err := time.Parse(numericDateFmt, s)
	if err != nil {
		return errors.Wrap(err, `failed to parse date format for jwt.NumericDate`)
	}

	*n = NumericDate{t}
	return nil
}

// NewClaimSet creates a new ClaimSet
func NewClaimSet() *ClaimSet {
	return &ClaimSet{
		EssentialClaims: &EssentialClaims{},
		PrivateClaims:   map[string]interface{}{},
	}
}

// MarshalJSON generates JSON representation of this claim set
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

// UnmarshalJSON parses the JSON representation and initializes this ClaimSet
func (c *ClaimSet) UnmarshalJSON(data []byte) error {
	if c.EssentialClaims == nil {
		c.EssentialClaims = &EssentialClaims{}
	}
	if c.PrivateClaims == nil {
		c.PrivateClaims = map[string]interface{}{}
	}
	return emap.MergeUnmarshal(data, c.EssentialClaims, &c.PrivateClaims)
}

// Construct takes a map and initializes the essential claims with its values
func (c *EssentialClaims) Construct(m map[string]interface{}) error {
	r := emap.Hmap(m)
	c.Audience, _ = r.GetStringSlice("aud")
	c.Expiration, _ = r.GetInt64("exp")
	c.IssuedAt, _ = r.GetInt64("iat")
	c.Issuer, _ = r.GetString("iss")
	c.JwtID, _ = r.GetString("jti")
	if v, err := r.GetString("nbf"); err == nil {
		if v != "" {
			t, err := time.Parse(numericDateFmt, v)
			if err != nil {
				return errors.Wrap(err, `failed to parse nbf value`)
			}
			c.NotBefore = &NumericDate{t}
		}
	}
	c.Subject, _ = r.GetString("sub")
	return nil
}

// Get retuns the value registered in this ClaimSet
// with the matching key name
func (c *ClaimSet) Get(key string) interface{} {
	switch key {
	case "aud":
		return c.Audience
	case "exp":
		return c.Expiration
	case "iat":
		return c.IssuedAt
	case "iss":
		return c.Issuer
	case "jti":
		return c.JwtID
	case "nbf":
		return c.NotBefore
	case "sub":
		return c.Subject
	}

	v, ok := c.PrivateClaims[key]
	if !ok {
		return nil
	}
	return v
}

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
		// for "aud", we allow either a string or a string slice
		switch value.(type) {
		case []string:
			c.Audience = value.([]string)
		case string:
			c.Audience = []string{value.(string)}
		default:
			return ErrInvalidValue
		}
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
			c.NotBefore = &NumericDate{value.(time.Time).UTC().Round(time.Second)}
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
