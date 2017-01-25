package jwt_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jws"
	"github.com/lestrrat/go-jwx/jwt"
	"github.com/stretchr/testify/assert"
)

func TestClaimSet(t *testing.T) {
	c1 := jwt.NewClaimSet()
	c1.Set("jti", "AbCdEfG")
	c1.Set("sub", "foobar@example.com")
	now := time.Now()
	c1.Set("iat", now)
	c1.Set("nbf", now.Add(5*time.Second))
	c1.Set("exp", now.Add(10*time.Second))
	c1.Set("custom", "MyValue")

	jsonbuf1, err := json.MarshalIndent(c1, "", "  ")
	if !assert.NoError(t, err, "JSON marshal should succeed") {
		return
	}
	t.Logf("%s", jsonbuf1)

	c2 := jwt.NewClaimSet()
	if !assert.NoError(t, json.Unmarshal(jsonbuf1, c2), "JSON unmarshal should succeed") {
		return
	}

	jsonbuf2, err := json.MarshalIndent(c2, "", "  ")
	if !assert.NoError(t, err, "JSON marshal should succeed") {
		return
	}
	t.Logf("%s", jsonbuf2)

	if !assert.Equal(t, c1, c2, "Claim sets match") {
		return
	}
}

func TestGHIssue10(t *testing.T) {
	c := jwt.NewClaimSet()
	c.Set("sub", "jwt-essential-claim-verification")

	// issuedat = 1 Hr before current time
	c.IssuedAt = time.Now().Unix() - 3600

	// valid for 2 minutes only from IssuedAt
	c.Expiration = c.IssuedAt + 120

	// NotBefore is set to future date
	tm := time.Now().Add(time.Duration(72) * time.Hour)
	c.NotBefore = &jwt.NumericDate{tm}

	//get json
	buf, err := json.MarshalIndent(c, "", "  ")
	if !assert.NoError(t, err, `generating JSON should succeed`) {
		return
	}

	// generte rsa key
	rsakey, err := rsa.GenerateKey(rand.Reader, 2048)
	if !assert.NoError(t, err, `generating private key should succeed`) {
		return
	}

	// sign payload
	sbuf, err := jws.Sign(buf, jwa.RS256, rsakey)
	if !assert.NoError(t, err, `jws.Sign should succeed`) {
		return
	}

	// Verify signature and grab payload
	verified, err := jws.Verify(sbuf, jwa.RS256, &rsakey.PublicKey)
	if !assert.NoError(t, err, `jws.Verify should succeed`) {

	}

	// Verify claims
	cs := jwt.NewClaimSet()
	if err = cs.UnmarshalJSON(verified); err != nil {
		t.Logf("failed to get claimset: %s", err)
		return
	}

	if !assert.Error(t, cs.Verify(), "claimset.Verify should fail") {
		t.Logf("JWS verified even expired!!!")
		// print Essential claims
		t.Logf("IssuedAt: %v", time.Unix(cs.IssuedAt, 0))
		t.Logf("Expiration: %v", time.Unix(cs.Expiration, 0))
		t.Logf("NotBefore: %v", cs.NotBefore)
		return
	}
}
