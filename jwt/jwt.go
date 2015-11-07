package jwt

import (
	"encoding/json"
	"fmt"
	"log"
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
	log.Printf("%#v", m)
	r := emap.Hmap(m)
	c.Audience, _ = r.GetString("aud")
	c.Expiration, _ = r.GetInt64("exp")
	c.IssuedAt, _ = r.GetInt64("iat")
	c.Issuer, _ = r.GetString("iss")
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
	c.JwtID, _ = r.GetString("jti")
	log.Printf("%#v", c)
	return nil
}
