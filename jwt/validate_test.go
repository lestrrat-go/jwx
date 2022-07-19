package jwt_test

import (
	"context"
	"errors"
	"log"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/internal/json"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGHIssue10(t *testing.T) {
	t.Parallel()

	// Simple string claims
	testcases := []struct {
		ClaimName  string
		ClaimValue string
		OptionFunc func(string) jwt.ValidateOption
		BuildFunc  func(v string) (jwt.Token, error)
	}{
		{
			ClaimName:  jwt.JwtIDKey,
			ClaimValue: `my-sepcial-key`,
			OptionFunc: jwt.WithJwtID,
			BuildFunc: func(v string) (jwt.Token, error) {
				return jwt.NewBuilder().
					JwtID(v).
					Build()
			},
		},
		{
			ClaimName:  jwt.SubjectKey,
			ClaimValue: `very important subject`,
			OptionFunc: jwt.WithSubject,
			BuildFunc: func(v string) (jwt.Token, error) {
				return jwt.NewBuilder().
					Subject(v).
					Build()
			},
		},
	}
	for _, tc := range testcases {
		tc := tc
		t.Run(tc.ClaimName, func(t *testing.T) {
			t.Parallel()
			t1, err := tc.BuildFunc(tc.ClaimValue)
			if !assert.NoError(t, err, `jwt.NewBuilder should succeed`) {
				return
			}

			// This should succeed, because validation option (tc.OptionFunc)
			// is not provided in the optional parameters
			if !assert.NoError(t, jwt.Validate(t1), "t1.Validate should succeed") {
				return
			}

			// This should succeed, because the option is provided with same value
			if !assert.NoError(t, jwt.Validate(t1, tc.OptionFunc(tc.ClaimValue)), "t1.Validate should succeed") {
				return
			}

			if !assert.Error(t, jwt.Validate(t1, jwt.WithIssuer("poop")), "t1.Validate should fail") {
				return
			}
		})
	}
	t.Run(jwt.IssuerKey, func(t *testing.T) {
		t.Parallel()
		t1, err := jwt.NewBuilder().
			Issuer("github.com/lestrrat-go/jwx/v2").
			Build()
		if !assert.NoError(t, err, `jwt.NewBuilder should succeed`) {
			return
		}

		// This should succeed, because WithIssuer is not provided in the
		// optional parameters
		if !assert.NoError(t, jwt.Validate(t1), "jwt.Validate should succeed") {
			return
		}

		// This should succeed, because WithIssuer is provided with same value
		if !assert.NoError(t, jwt.Validate(t1, jwt.WithIssuer(t1.Issuer())), "jwt.Validate should succeed") {
			return
		}

		err = jwt.Validate(t1, jwt.WithIssuer("poop"))
		if !assert.Error(t, err, "jwt.Validate should fail") {
			return
		}

		if !assert.ErrorIs(t, err, jwt.ErrInvalidIssuer(), "error should be jwt.ErrInvalidIssuer") {
			return
		}

		if !assert.True(t, jwt.IsValidationError(err), "error should be a validation error") {
			return
		}
	})
	t.Run(jwt.IssuedAtKey, func(t *testing.T) {
		t.Parallel()
		tm := time.Now()
		t1, err := jwt.NewBuilder().
			Claim(jwt.IssuedAtKey, tm).
			Build()
		if !assert.NoError(t, err, `jwt.NewBuilder should succeed`) {
			return
		}

		testcases := []struct {
			Name    string
			Options []jwt.ValidateOption
			Error   bool
		}{
			{
				Name:  `clock is set to before iat`,
				Error: true,
				Options: []jwt.ValidateOption{
					jwt.WithClock(jwt.ClockFunc(func() time.Time { return tm.Add(-1 * time.Hour) })),
				},
			},
			{
				// This works because the sub-second difference is rounded
				Name: `clock is set to some sub-seconds before iat`,
				Options: []jwt.ValidateOption{
					jwt.WithClock(jwt.ClockFunc(func() time.Time { return tm.Add(-1 * time.Millisecond) })),
				},
			},
			{
				Name:  `clock is set to some sub-seconds before iat (trunc = 0)`,
				Error: true,
				Options: []jwt.ValidateOption{
					jwt.WithClock(jwt.ClockFunc(func() time.Time { return tm.Add(-1 * time.Millisecond) })),
					jwt.WithTruncation(0),
				},
			},
		}

		for _, tc := range testcases {
			tc := tc
			t.Run(tc.Name, func(t *testing.T) {
				log.Printf("%s", tc.Name)
				err := jwt.Validate(t1, tc.Options...)
				if !tc.Error {
					assert.NoError(t, err, `jwt.Validate should succeed`)
					return
				}

				if !assert.Error(t, err, `jwt.Validate should fail`) {
					return
				}

				if !assert.True(t, errors.Is(err, jwt.ErrInvalidIssuedAt()), `error should be jwt.ErrInvalidIssuedAt`) {
					return
				}

				if !assert.False(t, errors.Is(err, jwt.ErrTokenNotYetValid()), `error should be not ErrNotYetValid`) {
					return
				}

				if !assert.True(t, jwt.IsValidationError(err), `error should be a validation error`) {
					return
				}
			})
		}
	})
	t.Run(jwt.AudienceKey, func(t *testing.T) {
		t.Parallel()
		t1, err := jwt.NewBuilder().
			Claim(jwt.AudienceKey, []string{"foo", "bar", "baz"}).
			Build()
		if !assert.NoError(t, err, `jwt.NewBuilder should succeed`) {
			return
		}

		// This should succeed, because WithAudience is not provided in the
		// optional parameters
		t.Run("`aud` check disabled", func(t *testing.T) {
			t.Parallel()
			if !assert.NoError(t, jwt.Validate(t1), `jwt.Validate should succeed`) {
				return
			}
		})

		// This should succeed, because WithAudience is provided, and its
		// value matches one of the audience values
		t.Run("`aud` contains `baz`", func(t *testing.T) {
			t.Parallel()
			if !assert.NoError(t, jwt.Validate(t1, jwt.WithAudience("baz")), "jwt.Validate should succeed") {
				return
			}
		})

		t.Run("check `aud` contains `poop`", func(t *testing.T) {
			t.Parallel()
			err := jwt.Validate(t1, jwt.WithAudience("poop"))
			if !assert.Error(t, err, "token.Validate should fail") {
				return
			}
			if !assert.ErrorIs(t, err, jwt.ErrInvalidAudience(), `error should be ErrInvalidAudience`) {
				return
			}
			if !assert.True(t, jwt.IsValidationError(err), `error should be a validation error`) {
				return
			}
		})
	})
	t.Run(jwt.SubjectKey, func(t *testing.T) {
		t.Parallel()
		t1, err := jwt.NewBuilder().
			Claim(jwt.SubjectKey, "github.com/lestrrat-go/jwx/v2").
			Build()
		if !assert.NoError(t, err, `jwt.NewBuilder should succeed`) {
			return
		}

		// This should succeed, because WithSubject is not provided in the
		// optional parameters
		if !assert.NoError(t, jwt.Validate(t1), "token.Validate should succeed") {
			return
		}

		// This should succeed, because WithSubject is provided with same value
		if !assert.NoError(t, jwt.Validate(t1, jwt.WithSubject(t1.Subject())), "token.Validate should succeed") {
			return
		}

		if !assert.Error(t, jwt.Validate(t1, jwt.WithSubject("poop")), "token.Validate should fail") {
			return
		}
	})
	t.Run(jwt.NotBeforeKey, func(t *testing.T) {
		t.Parallel()

		// NotBefore is set to future date
		tm := time.Now().Add(72 * time.Hour)

		t1, err := jwt.NewBuilder().
			Claim(jwt.NotBeforeKey, tm).
			Build()
		if !assert.NoError(t, err, `jwt.NewBuilder should succeed`) {
			return
		}

		testcases := []struct {
			Name    string
			Options []jwt.ValidateOption
			Error   bool
		}{
			{ // This should fail, because nbf is the future
				Name:  `'nbf' is less than current time`,
				Error: true,
			},
			{ // This should succeed, because we have given reaaaaaaly big skew
				Name: `skew is large enough`,
				Options: []jwt.ValidateOption{
					jwt.WithAcceptableSkew(73 * time.Hour),
				},
			},
			{ // This should succeed, because we have given a time
				// that is well enough into the future
				Name: `clock is set to some time after in nbf`,
				Options: []jwt.ValidateOption{
					jwt.WithClock(jwt.ClockFunc(func() time.Time { return tm.Add(time.Hour) })),
				},
			},
			{ // This should succeed, the time == NotBefore time
				// Note, this could fail if you are returning a monotonic clock
				// and we didn't do something about it
				Name: `clock is set to the same time as nbf`,
				Options: []jwt.ValidateOption{
					jwt.WithClock(jwt.ClockFunc(func() time.Time { return tm })),
				},
			},
			{
				Name:  `clock is set to some subseconds before nbf`,
				Error: true,
				Options: []jwt.ValidateOption{
					jwt.WithClock(jwt.ClockFunc(func() time.Time { return tm.Add(-1 * time.Millisecond) })),
					jwt.WithTruncation(0),
				},
			},
			{
				Name: `clock is set to some subseconds before nbf (but truncation = default)`,
				Options: []jwt.ValidateOption{
					jwt.WithClock(jwt.ClockFunc(func() time.Time { return tm.Add(-1 * time.Millisecond) })),
				},
			},
			{
				Name: `clock is set to some subseconds after nbf`,
				Options: []jwt.ValidateOption{
					jwt.WithClock(jwt.ClockFunc(func() time.Time { return tm.Add(time.Millisecond) })),
					jwt.WithTruncation(0),
				},
			},
		}
		for _, tc := range testcases {
			tc := tc
			t.Run(tc.Name, func(t *testing.T) {
				err := jwt.Validate(t1, tc.Options...)
				if !tc.Error {
					assert.NoError(t, err, "token.Validate should succeed")
					return
				}

				if !assert.Error(t, err, "token.Validate should fail") {
					return
				}
				if !assert.True(t, errors.Is(err, jwt.ErrTokenNotYetValid()), `error should be ErrTokenNotYetValid`) {
					return
				}
				if !assert.False(t, errors.Is(err, jwt.ErrTokenExpired()), `error should not be ErrTokenExpierd`) {
					return
				}
				if !assert.True(t, jwt.IsValidationError(err), `error should be a validation error`) {
					return
				}
			})
		}
	})
	t.Run(jwt.ExpirationKey, func(t *testing.T) {
		t.Parallel()

		tm := time.Now()
		t1, err := jwt.NewBuilder().
			// issuedat = 1 Hr before current time
			Claim(jwt.IssuedAtKey, tm.Add(-1*time.Hour)).
			// valid for 2 minutes only from IssuedAt
			Claim(jwt.ExpirationKey, tm).
			Build()
		if !assert.NoError(t, err, `jwt.NewBuilder should succeed`) {
			return
		}

		testcases := []struct {
			Name    string
			Options []jwt.ValidateOption
			Error   bool
		}{
			{
				Name:  `clock is not modified (exp < now)`,
				Error: true,
			},
			{
				Name: `clock is set to some time before exp`,
				Options: []jwt.ValidateOption{
					jwt.WithClock(jwt.ClockFunc(func() time.Time { return tm.Add(-1 * time.Hour) })),
				},
			},
			{ // This should fail, the time == Expiration.
				// Note, this could fail if you are returning a monotonic clock
				// and we didn't do something about it
				Name:  `clock is set to same time as exp`,
				Error: true,
				Options: []jwt.ValidateOption{
					jwt.WithClock(jwt.ClockFunc(func() time.Time { return tm })),
				},
			},
			{
				Name:  `clock is set to some subseconds after exp`,
				Error: true,
				Options: []jwt.ValidateOption{
					jwt.WithClock(jwt.ClockFunc(func() time.Time { return tm.Add(time.Millisecond) })),
					jwt.WithTruncation(0),
				},
			},
			{
				Name:  `clock is set to some subseconds after exp (but truncation = default)`,
				Error: true,
				Options: []jwt.ValidateOption{
					jwt.WithClock(jwt.ClockFunc(func() time.Time { return tm.Add(time.Millisecond) })),
				},
			},
			{
				Name: `clock is set to some subseconds before exp`,
				Options: []jwt.ValidateOption{
					jwt.WithClock(jwt.ClockFunc(func() time.Time { return tm.Add(-1 * time.Millisecond) })),
					jwt.WithTruncation(0),
				},
			},
		}

		for _, tc := range testcases {
			tc := tc
			t.Run(tc.Name, func(t *testing.T) {
				err := jwt.Validate(t1, tc.Options...)
				if !tc.Error {
					assert.NoError(t, err, `jwt.Validate should succeed`)
					return
				}

				require.Error(t, err, `jwt.Validate should fail`)
				if !assert.False(t, errors.Is(err, jwt.ErrTokenNotYetValid()), `error should not be ErrTokenNotYetValid`) {
					return
				}
				if !assert.True(t, errors.Is(err, jwt.ErrTokenExpired()), `error should be ErrTokenExpierd`) {
					return
				}
				if !assert.True(t, jwt.IsValidationError(err), `error should be a validation error`) {
					return
				}
			})
		}
	})
	t.Run("Unix zero times", func(t *testing.T) {
		t.Parallel()
		tm := time.Unix(0, 0)
		t1, err := jwt.NewBuilder().
			Claim(jwt.NotBeforeKey, tm).
			Claim(jwt.IssuedAtKey, tm).
			Claim(jwt.ExpirationKey, tm).
			Build()
		if !assert.NoError(t, err, `jwt.NewBuilder should succeed`) {
			return
		}

		// This should pass because the unix zero times should be ignored
		if assert.NoError(t, jwt.Validate(t1), "token.Validate should pass") {
			return
		}
	})
	t.Run("Go zero times", func(t *testing.T) {
		t.Parallel()
		tm := time.Time{}
		t1, err := jwt.NewBuilder().
			Claim(jwt.NotBeforeKey, tm).
			Claim(jwt.IssuedAtKey, tm).
			Claim(jwt.ExpirationKey, tm).
			Build()
		if !assert.NoError(t, err, `jwt.NewBuilder should succeed`) {
			return
		}

		// This should pass because the go zero times should be ignored
		if assert.NoError(t, jwt.Validate(t1), "token.Validate should pass") {
			return
		}
	})
	t.Run("Parse and validate", func(t *testing.T) {
		t.Parallel()
		tm := time.Now()
		t1, err := jwt.NewBuilder().
			// issuedat = 1 Hr before current time
			Claim(jwt.IssuedAtKey, tm.Add(-1*time.Hour)).
			// valid for 2 minutes only from IssuedAt
			Claim(jwt.ExpirationKey, tm.Add(-58*time.Minute)).
			Build()
		if !assert.NoError(t, err, `jwt.NewBuilder should succeed`) {
			return
		}

		buf, err := json.Marshal(t1)
		if !assert.NoError(t, err, `json.Marshal should succeed`) {
			return
		}

		_, err = jwt.Parse(buf, jwt.WithVerify(false), jwt.WithValidate(true))
		// This should fail, because exp is set in the past
		if !assert.Error(t, err, "jwt.Parse should fail") {
			return
		}

		_, err = jwt.Parse(buf, jwt.WithVerify(false), jwt.WithValidate(true), jwt.WithAcceptableSkew(time.Hour))
		// This should succeed, because we have given big skew
		// that is well enough to get us accepted
		if !assert.NoError(t, err, "jwt.Parse should succeed (1)") {
			return
		}

		// This should succeed, because we have given a time
		// that is well enough into the past
		clock := jwt.ClockFunc(func() time.Time {
			return tm.Add(-59 * time.Minute)
		})
		_, err = jwt.Parse(buf, jwt.WithVerify(false), jwt.WithValidate(true), jwt.WithClock(clock))
		if !assert.NoError(t, err, "jwt.Parse should succeed (2)") {
			return
		}
	})
	t.Run("any claim value", func(t *testing.T) {
		t.Parallel()
		t1, err := jwt.NewBuilder().
			Claim("email", "email@example.com").
			Build()
		if !assert.NoError(t, err, `jwt.NewBuilder should succeed`) {
			return
		}

		// This should succeed, because WithClaimValue("email", "xxx") is not provided in the
		// optional parameters
		if !assert.NoError(t, jwt.Validate(t1), "t1.Validate should succeed") {
			return
		}

		// This should succeed, because WithClaimValue is provided with same value
		if !assert.NoError(t, jwt.Validate(t1, jwt.WithClaimValue("email", "email@example.com")), "t1.Validate should succeed") {
			return
		}

		if !assert.Error(t, jwt.Validate(t1, jwt.WithClaimValue("email", "poop")), "t1.Validate should fail") {
			return
		}
		if !assert.Error(t, jwt.Validate(t1, jwt.WithClaimValue("xxxx", "email@example.com")), "t1.Validate should fail") {
			return
		}
		if !assert.Error(t, jwt.Validate(t1, jwt.WithClaimValue("xxxx", "")), "t1.Validate should fail") {
			return
		}
	})
}

func TestClaimValidator(t *testing.T) {
	t.Parallel()
	const myClaim = "my-claim"
	err0 := errors.New(myClaim + " does not exist")
	v := jwt.ValidatorFunc(func(_ context.Context, tok jwt.Token) jwt.ValidationError {
		_, ok := tok.Get(myClaim)
		if !ok {
			return jwt.NewValidationError(err0)
		}
		return nil
	})

	testcases := []struct {
		Name      string
		MakeToken func() jwt.Token
		Error     error
	}{
		{
			Name: "Successful validation",
			MakeToken: func() jwt.Token {
				t1 := jwt.New()
				_ = t1.Set(myClaim, map[string]interface{}{"k": "v"})
				return t1
			},
		},
		{
			Name: "Target claim does not exist",
			MakeToken: func() jwt.Token {
				t1 := jwt.New()
				_ = t1.Set("other-claim", map[string]interface{}{"k": "v"})
				return t1
			},
			Error: err0,
		},
	}
	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()
			t1 := tc.MakeToken()
			if err := tc.Error; err != nil {
				if !assert.ErrorIs(t, jwt.Validate(t1, jwt.WithValidator(v)), err) {
					return
				}
				return
			}

			if !assert.NoError(t, jwt.Validate(t1, jwt.WithValidator(v))) {
				return
			}
		})
	}
}
