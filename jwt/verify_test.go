package jwt_test

import (
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jwt"
	"github.com/stretchr/testify/assert"
)

func TestGHIssue10(t *testing.T) {
	t.Run(jwt.IssuerKey, func(t *testing.T) {
		t1 := jwt.New()
		t1.Set(jwt.IssuerKey, "github.com/lestrrat-go/jwx")

		// This should succeed, because WithIssuer is not provided in the
		// optional parameters
		if !assert.NoError(t, t1.Verify(), "t1.Verify should succeed") {
			return
		}

		// This should succeed, because WithIssuer is provided with same value
		if !assert.NoError(t, t1.Verify(jwt.WithIssuer(t1.Issuer())), "t1.Verify should succeed") {
			return
		}

		if !assert.Error(t, t1.Verify(jwt.WithIssuer("poop")), "t1.Verify should fail") {
			return
		}
	})
	t.Run(jwt.AudienceKey, func(t *testing.T) {
		t1 := jwt.New()
		err := t1.Set(jwt.AudienceKey, []string{"foo", "bar", "baz"})
		if err != nil {
			t.Fatalf("Failed to set audience claim: %s", err.Error())
		}

		// This should succeed, because WithAudience is not provided in the
		// optional parameters
		err = t1.Verify()
		if err != nil {
			t.Fatalf("Error varifying claim: %s", err.Error())
		}

		// This should succeed, because WithAudience is provided, and its
		// value matches one of the audience values
		if !assert.NoError(t, t1.Verify(jwt.WithAudience("baz")), "token.Verify should succeed") {
			return
		}

		if !assert.Error(t, t1.Verify(jwt.WithAudience("poop")), "token.Verify should fail") {
			return
		}
	})
	t.Run(jwt.SubjectKey, func(t *testing.T) {
		t1 := jwt.New()
		t1.Set(jwt.SubjectKey, "github.com/lestrrat-go/jwx")

		// This should succeed, because WithSubject is not provided in the
		// optional parameters
		if !assert.NoError(t, t1.Verify(), "token.Verify should succeed") {
			return
		}

		// This should succeed, because WithSubject is provided with same value
		if !assert.NoError(t, t1.Verify(jwt.WithSubject(t1.Subject())), "token.Verify should succeed") {
			return
		}

		if !assert.Error(t, t1.Verify(jwt.WithSubject("poop")), "token.Verify should fail") {
			return
		}
	})
	t.Run(jwt.NotBeforeKey, func(t *testing.T) {
		t1 := jwt.New()

		// NotBefore is set to future date
		tm := time.Now().Add(72 * time.Hour)
		t1.Set(jwt.NotBeforeKey, tm)

		// This should fail, because nbf is the future
		if !assert.Error(t, t1.Verify(), "token.Verify should fail") {
			return
		}

		// This should succeed, because we have given reaaaaaaly big skew
		// that is well enough to get us accepted
		if !assert.NoError(t, t1.Verify(jwt.WithAcceptableSkew(73*time.Hour)), "token.Verify should succeed") {
			return
		}

		// This should succeed, because we have given a time
		// that is well enough into the future
		if !assert.NoError(t, t1.Verify(jwt.WithClock(jwt.ClockFunc(func() time.Time { return tm.Add(time.Hour) }))), "token.Verify should succeed") {
			return
		}
	})
	t.Run(jwt.ExpirationKey, func(t *testing.T) {
		t1 := jwt.New()

		// issuedat = 1 Hr before current time
		tm := time.Now()
		t1.Set(jwt.IssuedAtKey, tm.Add(-1*time.Hour))

		// valid for 2 minutes only from IssuedAt
		t1.Set(jwt.ExpirationKey, tm.Add(-58*time.Minute))

		// This should fail, because exp is set in the past
		if !assert.Error(t, t1.Verify(), "token.Verify should fail") {
			return
		}

		// This should succeed, because we have given big skew
		// that is well enough to get us accepted
		if !assert.NoError(t, t1.Verify(jwt.WithAcceptableSkew(time.Hour)), "token.Verify should succeed (1)") {
			return
		}

		// This should succeed, because we have given a time
		// that is well enough into the past
		clock := jwt.ClockFunc(func() time.Time {
			return tm.Add(-59 * time.Minute)
		})
		if !assert.NoError(t, t1.Verify(jwt.WithClock(clock)), "token.Verify should succeed (2)") {
			return
		}
	})
}
