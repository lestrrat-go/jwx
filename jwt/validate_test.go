package jwt_test

import (
	"context"
	"errors"
	"log"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/internal/json"
	"github.com/lestrrat-go/jwx/v3/jwt"
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
		t.Run(tc.ClaimName, func(t *testing.T) {
			t.Parallel()
			t1, err := tc.BuildFunc(tc.ClaimValue)
			require.NoError(t, err, `jwt.NewBuilder should succeed`)

			// This should succeed, because validation option (tc.OptionFunc)
			// is not provided in the optional parameters
			require.NoError(t, jwt.Validate(t1), "t1.Validate should succeed")

			// This should succeed, because the option is provided with same value
			require.NoError(t, jwt.Validate(t1, tc.OptionFunc(tc.ClaimValue)), "t1.Validate should succeed")
			require.Error(t, jwt.Validate(t1, jwt.WithIssuer("poop")), "t1.Validate should fail")
		})
	}
	t.Run(jwt.IssuerKey, func(t *testing.T) {
		t.Parallel()
		t1, err := jwt.NewBuilder().
			Issuer("github.com/lestrrat-go/jwx/v3").
			Build()
		require.NoError(t, err, `jwt.NewBuilder should succeed`)

		// This should succeed, because WithIssuer is not provided in the
		// optional parameters
		require.NoError(t, jwt.Validate(t1), "jwt.Validate should succeed")

		// This should succeed, because WithIssuer is provided with same value
		iss, ok := t1.Issuer()
		require.True(t, ok, `t1.Issuer should succeed`)
		require.NoError(t, jwt.Validate(t1, jwt.WithIssuer(iss)), "jwt.Validate should succeed")

		err = jwt.Validate(t1, jwt.WithIssuer("poop"))
		require.Error(t, err, "jwt.Validate should fail")
		require.ErrorIs(t, err, jwt.ErrInvalidIssuer(), "error should be jwt.ErrInvalidIssuer")
		require.True(t, jwt.IsValidationError(err), "error should be a validation error")
	})
	t.Run(jwt.IssuedAtKey, func(t *testing.T) {
		t.Parallel()
		tm := time.Now()
		t1, err := jwt.NewBuilder().
			Claim(jwt.IssuedAtKey, tm).
			Build()
		require.NoError(t, err, `jwt.NewBuilder should succeed`)
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
			t.Run(tc.Name, func(t *testing.T) {
				log.Printf("%s", tc.Name)
				err := jwt.Validate(t1, tc.Options...)
				if !tc.Error {
					require.NoError(t, err, `jwt.Validate should succeed`)
					return
				}

				require.Error(t, err, `jwt.Validate should fail`)
				require.True(t, errors.Is(err, jwt.ErrInvalidIssuedAt()), `error should be jwt.ErrInvalidIssuedAt`)
				require.False(t, errors.Is(err, jwt.ErrTokenNotYetValid()), `error should be not ErrNotYetValid`)
				require.True(t, jwt.IsValidationError(err), `error should be a validation error`)
			})
		}
	})
	t.Run(jwt.AudienceKey, func(t *testing.T) {
		t.Parallel()
		t1, err := jwt.NewBuilder().
			Claim(jwt.AudienceKey, []string{"foo", "bar", "baz"}).
			Build()
		require.NoError(t, err, `jwt.NewBuilder should succeed`)

		// This should succeed, because WithAudience is not provided in the
		// optional parameters
		t.Run("`aud` check disabled", func(t *testing.T) {
			t.Parallel()
			require.NoError(t, jwt.Validate(t1), `jwt.Validate should succeed`)
		})

		// This should succeed, because WithAudience is provided, and its
		// value matches one of the audience values
		t.Run("`aud` contains `baz`", func(t *testing.T) {
			t.Parallel()
			require.NoError(t, jwt.Validate(t1, jwt.WithAudience("baz")), "jwt.Validate should succeed")
		})

		t.Run("check `aud` contains `poop`", func(t *testing.T) {
			t.Parallel()
			err := jwt.Validate(t1, jwt.WithAudience("poop"))
			require.Error(t, err, "token.Validate should fail")
			require.ErrorIs(t, err, jwt.ErrInvalidAudience(), `error should be ErrInvalidAudience`)
			require.True(t, jwt.IsValidationError(err), `error should be a validation error`)
		})
	})
	t.Run(jwt.SubjectKey, func(t *testing.T) {
		t.Parallel()
		t1, err := jwt.NewBuilder().
			Claim(jwt.SubjectKey, "github.com/lestrrat-go/jwx/v3").
			Build()
		require.NoError(t, err, `jwt.NewBuilder should succeed`)

		// This should succeed, because WithSubject is not provided in the
		// optional parameters
		require.NoError(t, jwt.Validate(t1), "token.Validate should succeed")

		// This should succeed, because WithSubject is provided with same value
		sub, ok := t1.Subject()
		require.True(t, ok, `t1.Subject should succeed`)
		require.NoError(t, jwt.Validate(t1, jwt.WithSubject(sub)), "token.Validate should succeed")
		require.Error(t, jwt.Validate(t1, jwt.WithSubject("poop")), "token.Validate should fail")
	})
	t.Run(jwt.NotBeforeKey, func(t *testing.T) {
		t.Parallel()

		// NotBefore is set to future date
		tm := time.Now().Add(72 * time.Hour)

		t1, err := jwt.NewBuilder().
			Claim(jwt.NotBeforeKey, tm).
			Build()
		require.NoError(t, err, `jwt.NewBuilder should succeed`)
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
				Name:  `clock is set to some sub-seconds before nbf`,
				Error: true,
				Options: []jwt.ValidateOption{
					jwt.WithClock(jwt.ClockFunc(func() time.Time { return tm.Add(-1 * time.Millisecond) })),
					jwt.WithTruncation(0),
				},
			},
			{
				Name: `clock is set to some sub-seconds before nbf (but truncation = default)`,
				Options: []jwt.ValidateOption{
					jwt.WithClock(jwt.ClockFunc(func() time.Time { return tm.Add(-1 * time.Millisecond) })),
				},
			},
			{
				Name: `clock is set to some sub-seconds after nbf`,
				Options: []jwt.ValidateOption{
					jwt.WithClock(jwt.ClockFunc(func() time.Time { return tm.Add(time.Millisecond) })),
					jwt.WithTruncation(0),
				},
			},
		}
		for _, tc := range testcases {
			t.Run(tc.Name, func(t *testing.T) {
				err := jwt.Validate(t1, tc.Options...)
				if !tc.Error {
					require.NoError(t, err, "token.Validate should succeed")
					return
				}

				require.Error(t, err, "token.Validate should fail")
				require.True(t, errors.Is(err, jwt.ErrTokenNotYetValid()), `error should be ErrTokenNotYetValid`)
				require.False(t, errors.Is(err, jwt.ErrTokenExpired()), `error should not be ErrTokenExpired`)
				require.True(t, jwt.IsValidationError(err), `error should be a validation error`)
			})
		}
	})
	t.Run(jwt.ExpirationKey, func(t *testing.T) {
		t.Parallel()

		tm := time.Now()
		t1, err := jwt.NewBuilder().
			// issuedAt = 1 Hr before current time
			Claim(jwt.IssuedAtKey, tm.Add(-1*time.Hour)).
			// valid for 2 minutes only from IssuedAt
			Claim(jwt.ExpirationKey, tm).
			Build()
		require.NoError(t, err, `jwt.NewBuilder should succeed`)
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
				Name:  `clock is set to some sub-seconds after exp`,
				Error: true,
				Options: []jwt.ValidateOption{
					jwt.WithClock(jwt.ClockFunc(func() time.Time { return tm.Add(time.Millisecond) })),
					jwt.WithTruncation(0),
				},
			},
			{
				Name:  `clock is set to some sub-seconds after exp (but truncation = default)`,
				Error: true,
				Options: []jwt.ValidateOption{
					jwt.WithClock(jwt.ClockFunc(func() time.Time { return tm.Add(time.Millisecond) })),
				},
			},
			{
				Name: `clock is set to some sub-seconds before exp`,
				Options: []jwt.ValidateOption{
					jwt.WithClock(jwt.ClockFunc(func() time.Time { return tm.Add(-1 * time.Millisecond) })),
					jwt.WithTruncation(0),
				},
			},
		}

		for _, tc := range testcases {
			t.Run(tc.Name, func(t *testing.T) {
				err := jwt.Validate(t1, tc.Options...)
				if !tc.Error {
					require.NoError(t, err, `jwt.Validate should succeed`)
					return
				}

				require.Error(t, err, `jwt.Validate should fail`)
				require.False(t, errors.Is(err, jwt.ErrTokenNotYetValid()), `error should not be ErrTokenNotYetValid`)
				require.True(t, errors.Is(err, jwt.ErrTokenExpired()), `error should be ErrTokenExpired`)
				require.True(t, jwt.IsValidationError(err), `error should be a validation error`)
			})
		}
	})
	t.Run("Unix zero times", func(t *testing.T) {
		// See comments at ref: handling iat, nbf, and exp in v3
		t.Parallel()
		// tm := time.Unix(0, 0)
		t1, err := jwt.NewBuilder().
			//Claim(jwt.NotBeforeKey, tm).
			//Claim(jwt.IssuedAtKey, tm).
			//Claim(jwt.ExpirationKey, tm).
			Build()
		require.NoError(t, err, `jwt.NewBuilder should succeed`)

		// This should pass because the unix zero times should be ignored
		require.NoError(t, jwt.Validate(t1), "token.Validate should pass")
	})
	t.Run("Go zero times", func(t *testing.T) {
		// ref: handling iat, nbf, and exp in v3
		// Previously (v2) we used to treat the zero value as the same as
		// the field not existing, but this is no longer true.
		//
		// This test/ used to pass in v2 even when we set exp to time.Time{},
		// but it is no longer the case in v3. To emulate the previous
		// behavior, we need to _NOT_ set the exp field at all
		t.Parallel()
		tm := time.Time{}
		t1, err := jwt.NewBuilder().
			Claim(jwt.NotBeforeKey, tm).
			Claim(jwt.IssuedAtKey, tm).
			// Claim(jwt.ExpirationKey, tm). // Omit this
			Build()
		require.NoError(t, err, `jwt.NewBuilder should succeed`)

		// This should pass because the go zero times should be ignored
		require.NoError(t, jwt.Validate(t1), "token.Validate should pass")
	})
	t.Run("Parse and validate", func(t *testing.T) {
		t.Parallel()
		tm := time.Now()
		t1, err := jwt.NewBuilder().
			// issuedAt = 1 Hr before current time
			Claim(jwt.IssuedAtKey, tm.Add(-1*time.Hour)).
			// valid for 2 minutes only from IssuedAt
			Claim(jwt.ExpirationKey, tm.Add(-58*time.Minute)).
			Build()
		require.NoError(t, err, `jwt.NewBuilder should succeed`)

		buf, err := json.Marshal(t1)
		require.NoError(t, err, `json.Marshal should succeed`)

		_, err = jwt.Parse(buf, jwt.WithVerify(false), jwt.WithValidate(true))
		// This should fail, because exp is set in the past
		require.Error(t, err, "jwt.Parse should fail")

		_, err = jwt.Parse(buf, jwt.WithVerify(false), jwt.WithValidate(true), jwt.WithAcceptableSkew(time.Hour))
		// This should succeed, because we have given big skew
		// that is well enough to get us accepted
		require.NoError(t, err, "jwt.Parse should succeed (1)")

		// This should succeed, because we have given a time
		// that is well enough into the past
		clock := jwt.ClockFunc(func() time.Time {
			return tm.Add(-59 * time.Minute)
		})
		_, err = jwt.Parse(buf, jwt.WithVerify(false), jwt.WithValidate(true), jwt.WithClock(clock))
		require.NoError(t, err, "jwt.Parse should succeed (2)")
	})
	t.Run("any claim value", func(t *testing.T) {
		t.Parallel()
		t1, err := jwt.NewBuilder().
			Claim("email", "email@example.com").
			Build()
		require.NoError(t, err, `jwt.NewBuilder should succeed`)

		// This should succeed, because WithClaimValue("email", "xxx") is not provided in the
		// optional parameters
		require.NoError(t, jwt.Validate(t1), "t1.Validate should succeed")

		// This should succeed, because WithClaimValue is provided with same value
		require.NoError(t, jwt.Validate(t1, jwt.WithClaimValue("email", "email@example.com")), "t1.Validate should succeed")
		require.Error(t, jwt.Validate(t1, jwt.WithClaimValue("email", "poop")), "t1.Validate should fail")
		require.Error(t, jwt.Validate(t1, jwt.WithClaimValue("xxxx", "email@example.com")), "t1.Validate should fail")
		require.Error(t, jwt.Validate(t1, jwt.WithClaimValue("xxxx", "")), "t1.Validate should fail")
	})
}

func TestClaimValidator(t *testing.T) {
	t.Parallel()
	const myClaim = "my-claim"
	err0 := errors.New(myClaim + " does not exist")
	v := jwt.ValidatorFunc(func(_ context.Context, tok jwt.Token) jwt.ValidationError {
		if !tok.Has(myClaim) {
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
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()
			t1 := tc.MakeToken()
			if err := tc.Error; err != nil {
				require.ErrorIs(t, jwt.Validate(t1, jwt.WithValidator(v)), err)
				return
			}

			require.NoError(t, jwt.Validate(t1, jwt.WithValidator(v)))
		})
	}
}
