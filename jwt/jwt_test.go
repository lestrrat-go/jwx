package jwt_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/lestrrat/go-jwx/jwt"
	"github.com/stretchr/testify/assert"
)

func TestClaimSet(t *testing.T) {
	c1 := jwt.NewClaimSet()
	if !assert.NoError(t, c1.Set("jti", "AbCdEfG"), "setting jti should work") {
		return
	}
	if !assert.NoError(t, c1.Set("sub", "foobar@example.com"), "setting sub should work") {
		return
	}

	// Silly fix to remove monotonic element from time.Time obatained
	// from time.Now(). Without this, the equality comparison goes
	// ga-ga for golang tip (1.9)
	now := time.Unix(time.Now().Unix(), 0)
	if !assert.NoError(t, c1.Set("iat", now.Unix()), "setting iat to now should work") {
		return
	}
	if !assert.NoError(t, c1.Set("nbf", now.Add(5*time.Second)), "setting nbf should work") {
		return
	}
	if !assert.NoError(t, c1.Set("exp", now.Add(10*time.Second).Unix()), "setting exp should work") {
		return
	}
	if !assert.NoError(t, c1.Set("custom", "MyValue"), "setting custom should work") {
		return
	}

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

func TestGHIssue10_iss(t *testing.T) {
	c := jwt.NewClaimSet()
	c.Issuer = "github.com/lestrrat/go-jwx"

	// This should succeed, because WithIssuer is not provided in the
	// optinal parameters
	if !assert.NoError(t, c.Verify(), "claimset.Verify should succeed") {
		return
	}

	// This should succeed, because WithIssuer is provided with same value
	if !assert.NoError(t, c.Verify(jwt.WithIssuer(c.Issuer)), "claimset.Verify should succeed") {
		return
	}

	if !assert.Error(t, c.Verify(jwt.WithIssuer("poop")), "claimset.Verify should fail") {
		return
	}
}

func TestGHIssue10_aud(t *testing.T) {
	c := jwt.NewClaimSet()
	c.Audience = []string{
		"foo",
		"bar",
		"baz",
	}

	// This should succeed, because WithAudience is not provided in the
	// optinal parameters
	if !assert.NoError(t, c.Verify(), "claimset.Verify should succeed") {
		return
	}

	// This should succeed, because WithAudience is provided, and its
	// value matches one of the audience values
	if !assert.NoError(t, c.Verify(jwt.WithAudience("baz")), "claimset.Verify should succeed") {
		return
	}

	if !assert.Error(t, c.Verify(jwt.WithAudience("poop")), "claimset.Verify should fail") {
		return
	}
}

func TestGHIssue10_sub(t *testing.T) {
	c := jwt.NewClaimSet()
	c.Subject = "github.com/lestrrat/go-jwx"

	// This should succeed, because WithSubject is not provided in the
	// optinal parameters
	if !assert.NoError(t, c.Verify(), "claimset.Verify should succeed") {
		return
	}

	// This should succeed, because WithSubject is provided with same value
	if !assert.NoError(t, c.Verify(jwt.WithSubject(c.Subject)), "claimset.Verify should succeed") {
		return
	}

	if !assert.Error(t, c.Verify(jwt.WithSubject("poop")), "claimset.Verify should fail") {
		return
	}
}

func TestGHIssue10_nbf(t *testing.T) {
	c := jwt.NewClaimSet()

	// NotBefore is set to future date
	tm := time.Now().Add(72 * time.Hour)
	c.NotBefore = &jwt.NumericDate{tm}

	// This should fail, because nbf is the future
	if !assert.Error(t, c.Verify(), "claimset.Verify should fail") {
		return
	}

	// This should succeed, because we have given reaaaaaaly big skew
	// that is well enough to get us accepted
	if !assert.NoError(t, c.Verify(jwt.WithAcceptableSkew(73*time.Hour)), "claimset.Verify should succeed") {
		return
	}

	// This should succeed, because we have given a time
	// that is well enough into the future
	if !assert.NoError(t, c.Verify(jwt.WithClock(jwt.ClockFunc(func() time.Time { return tm.Add(time.Hour) }))), "claimset.Verify should succeed") {
		return
	}
}

func TestGHIssue10_exp(t *testing.T) {
	c := jwt.NewClaimSet()

	// issuedat = 1 Hr before current time
	tm := time.Now()
	c.IssuedAt = tm.Unix() - 3600

	// valid for 2 minutes only from IssuedAt
	c.Expiration = c.IssuedAt + 120

	// This should fail, because exp is set in the past
	if !assert.Error(t, c.Verify(), "claimset.Verify should fail") {
		return
	}

	// This should succeed, because we have given big skew
	// that is well enough to get us accepted
	if !assert.NoError(t, c.Verify(jwt.WithAcceptableSkew(time.Hour)), "claimset.Verify should succeed") {
		return
	}

	// This should succeed, because we have given a time
	// that is well enough into the past
	if !assert.NoError(t, c.Verify(jwt.WithClock(jwt.ClockFunc(func() time.Time { return tm.Add(-3500 * time.Second) }))), "claimset.Verify should succeed") {
		return
	}
}
