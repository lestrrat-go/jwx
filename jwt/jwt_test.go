package jwt_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat/go-jwx/jwt"
	"github.com/stretchr/testify/assert"
)

func TestToken(t *testing.T) {
	t1 := jwt.New()
	if !assert.NoError(t, t1.Set(jwt.JwtIDKey, "AbCdEfG"), "setting jti should work") {
		return
	}
	if !assert.NoError(t, t1.Set(jwt.SubjectKey, "foobar@example.com"), "setting sub should work") {
		return
	}

	// Silly fix to remove monotonic element from time.Time obatained
	// from time.Now(). Without this, the equality comparison goes
	// ga-ga for golang tip (1.9)
	now := time.Unix(time.Now().Unix(), 0)
	if !assert.NoError(t, t1.Set(jwt.IssuedAtKey, now.Unix()), "setting iat to now should work") {
		return
	}
	if !assert.NoError(t, t1.Set(jwt.NotBeforeKey, now.Add(5*time.Second)), "setting nbf should work") {
		return
	}
	if !assert.NoError(t, t1.Set(jwt.ExpirationKey, now.Add(10*time.Second).Unix()), "setting exp should work") {
		return
	}
	if !assert.NoError(t, t1.Set("custom", "MyValue"), "setting custom should work") {
		return
	}

	jsonbuf1, err := json.MarshalIndent(t1, "", "  ")
	if !assert.NoError(t, err, "JSON marshal should succeed") {
		return
	}
	t.Logf("%s", jsonbuf1)

	var t2 jwt.Token
	if !assert.NoError(t, json.Unmarshal(jsonbuf1, &t2), "JSON unmarshal should succeed") {
		return
	}

	jsonbuf2, err := json.MarshalIndent(t2, "", "  ")
	if !assert.NoError(t, err, "JSON marshal should succeed") {
		return
	}
	t.Logf("%s", jsonbuf2)

	if !assert.Equal(t, t1, &t2, "tokens match") {
		return
	}
}

func TestGHIssue10(t *testing.T) {
	t.Run(jwt.IssuerKey, func(t *testing.T) {
		t1 := jwt.New()
		t1.Set(jwt.IssuerKey, "github.com/lestrrat/go-jwx")

		// This should succeed, because WithIssuer is not provided in the
		// optinal parameters
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
		t1.Set(jwt.AudienceKey, []string{
			"foo",
			"bar",
			"baz",
		})

		// This should succeed, because WithAudience is not provided in the
		// optinal parameters
		if !assert.NoError(t, t1.Verify(), "token.Verify should succeed") {
			return
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
		t1.Set(jwt.SubjectKey, "github.com/lestrrat/go-jwx")

		// This should succeed, because WithSubject is not provided in the
		// optinal parameters
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
			return tm.Add(-59*time.Minute)
		})
		if !assert.NoError(t, t1.Verify(jwt.WithClock(clock)), "token.Verify should succeed (2)") {
			return
		}
	})
}

const aLongLongTimeAgo = 233431200
const aLongLongTimeAgoString = "233431200"

func TestUnmarshal(t *testing.T) {
	testcases := []struct {
		Title    string
		JSON     string
		Expected func() *jwt.Token
	}{
		{
			Title: "single aud",
			JSON:  `{"aud":"foo"}`,
			Expected: func() *jwt.Token {
				t := jwt.New()
				t.Set("aud", "foo")
				return t
			},
		},
		{
			Title: "multiple aud's",
			JSON:  `{"aud":["foo","bar"]}`,
			Expected: func() *jwt.Token {
				t := jwt.New()
				t.Set("aud", []string{"foo", "bar"})
				return t
			},
		},
		{
			Title: "issuedAt",
			JSON:  `{"` + jwt.IssuedAtKey + `":` + aLongLongTimeAgoString + `}`,
			Expected: func() *jwt.Token {
				t := jwt.New()
				t.Set(jwt.IssuedAtKey, aLongLongTimeAgo)
				return t
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.Title, func(t *testing.T) {
			var token jwt.Token
			if !assert.NoError(t, json.Unmarshal([]byte(tc.JSON), &token), `json.Unmarshal should succeed`) {
				return
			}
			if !assert.Equal(t, tc.Expected(), &token, `token should match expeted value`) {
				return
			}

			var buf bytes.Buffer
			if !assert.NoError(t, json.NewEncoder(&buf).Encode(token), `json.Marshal should succeed`) {
				return
			}
			if !assert.Equal(t, tc.JSON, strings.TrimSpace(buf.String()), `json should match`) {
				return
			}
		})
	}
}

func TestGet(t *testing.T) {
	testcases := []struct {
		Title string
		Test  func(*testing.T, *jwt.Token)
		Token func() *jwt.Token
	}{
		{
			Title: `Get IssuedAt`,
			Test: func(t *testing.T, token *jwt.Token) {
				expected := time.Unix(aLongLongTimeAgo, 0)
				if !assert.Equal(t, expected, token.IssuedAt(), `IssuedAt should match`) {
					return
				}
			},
			Token: func() *jwt.Token {
				t := jwt.New()
				t.Set(jwt.IssuedAtKey, 233431200)
				return t
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.Title, func(t *testing.T) {
			tc.Test(t, tc.Token())
		})
	}
}
