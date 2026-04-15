package jwt_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/require"
)

func TestStructuredErrors(t *testing.T) {
	t.Parallel()

	t.Run("TokenExpiredError carries structured fields", func(t *testing.T) {
		t.Parallel()

		expTime := time.Now().Add(-1 * time.Hour).Truncate(0)
		tok, err := jwt.NewBuilder().
			Expiration(expTime).
			Build()
		require.NoError(t, err)

		err = jwt.Validate(tok)
		require.Error(t, err)

		require.ErrorIs(t, err, jwt.TokenExpiredError{})
		require.ErrorIs(t, err, jwt.ValidationError{})

		expErr, ok := errors.AsType[jwt.TokenExpiredError](err)
		require.True(t, ok, "errors.AsType should find TokenExpiredError")
		require.False(t, expErr.Expiration.IsZero(), "Expiration should be populated")
		require.False(t, expErr.Now.IsZero(), "Now should be populated")
	})

	t.Run("TokenNotYetValidError carries structured fields", func(t *testing.T) {
		t.Parallel()

		nbfTime := time.Now().Add(72 * time.Hour).Truncate(0)
		tok, err := jwt.NewBuilder().
			NotBefore(nbfTime).
			Build()
		require.NoError(t, err)

		err = jwt.Validate(tok)
		require.Error(t, err)

		require.ErrorIs(t, err, jwt.TokenNotYetValidError{})
		require.ErrorIs(t, err, jwt.ValidationError{})

		nbfErr, ok := errors.AsType[jwt.TokenNotYetValidError](err)
		require.True(t, ok, "errors.AsType should find TokenNotYetValidError")
		require.False(t, nbfErr.NotBefore.IsZero(), "NotBefore should be populated")
		require.False(t, nbfErr.Now.IsZero(), "Now should be populated")
	})

	t.Run("InvalidIssuedAtError carries structured fields", func(t *testing.T) {
		t.Parallel()

		iatTime := time.Now().Add(72 * time.Hour).Truncate(0)
		tok, err := jwt.NewBuilder().
			IssuedAt(iatTime).
			Build()
		require.NoError(t, err)

		err = jwt.Validate(tok)
		require.Error(t, err)

		require.ErrorIs(t, err, jwt.InvalidIssuedAtError{})
		require.ErrorIs(t, err, jwt.ValidationError{})

		iatErr, ok := errors.AsType[jwt.InvalidIssuedAtError](err)
		require.True(t, ok, "errors.AsType should find InvalidIssuedAtError")
		require.False(t, iatErr.IssuedAt.IsZero(), "IssuedAt should be populated")
		require.False(t, iatErr.Now.IsZero(), "Now should be populated")
	})

	t.Run("ClaimValidationError from ClaimValueIs", func(t *testing.T) {
		t.Parallel()

		tok, err := jwt.NewBuilder().
			Subject("actual-subject").
			Build()
		require.NoError(t, err)

		err = jwt.Validate(tok,
			jwt.WithValidator(jwt.ClaimValueIs(jwt.SubjectKey, "expected-subject")),
		)
		require.Error(t, err)

		claimErr, ok := errors.AsType[jwt.ClaimValidationError](err)
		require.True(t, ok, "errors.AsType should find ClaimValidationError")
		require.Equal(t, jwt.SubjectKey, claimErr.Claim)
		require.Equal(t, "expected-subject", claimErr.Expected)
		require.Equal(t, "actual-subject", claimErr.Actual)

		// Error() message must not leak claim values via fmt verbs.
		// See ClaimValidationError godoc.
		for _, verb := range []string{"%s", "%v", "%+v"} {
			msg := fmt.Sprintf(verb, err)
			require.NotContains(t, msg, "expected-subject", verb)
			require.NotContains(t, msg, "actual-subject", verb)
		}
	})

	t.Run("ClaimValidationError from ClaimContainsString", func(t *testing.T) {
		t.Parallel()

		tok, err := jwt.NewBuilder().
			Claim("groups", []string{"admin", "user"}).
			Build()
		require.NoError(t, err)

		err = jwt.Validate(tok,
			jwt.WithValidator(jwt.ClaimContainsString("groups", "superadmin")),
		)
		require.Error(t, err)

		claimErr, ok := errors.AsType[jwt.ClaimValidationError](err)
		require.True(t, ok, "errors.AsType should find ClaimValidationError")
		require.Equal(t, "groups", claimErr.Claim)
		require.Equal(t, "superadmin", claimErr.Expected)
		require.Equal(t, []string{"admin", "user"}, claimErr.Actual)

		for _, verb := range []string{"%s", "%v", "%+v"} {
			msg := fmt.Sprintf(verb, err)
			require.NotContains(t, msg, "superadmin", verb)
			require.NotContains(t, msg, "admin", verb)
		}
	})

	t.Run("issuer/audience still use typed errors not ClaimValidationError", func(t *testing.T) {
		t.Parallel()

		tok, err := jwt.NewBuilder().
			Issuer("real-issuer").
			Audience([]string{"real-aud"}).
			Build()
		require.NoError(t, err)

		// Issuer mismatch
		err = jwt.Validate(tok, jwt.WithIssuer("wrong-issuer"))
		require.Error(t, err)
		require.ErrorIs(t, err, jwt.InvalidIssuerError{})
		_, ok := errors.AsType[jwt.ClaimValidationError](err)
		require.False(t, ok, "issuer error should not be ClaimValidationError")

		// Audience mismatch
		err = jwt.Validate(tok, jwt.WithAudience("wrong-aud"))
		require.Error(t, err)
		require.ErrorIs(t, err, jwt.InvalidAudienceError{})
		_, ok = errors.AsType[jwt.ClaimValidationError](err)
		require.False(t, ok, "audience error should not be ClaimValidationError")
	})

	t.Run("TimeDeltaError from MaxDeltaIs", func(t *testing.T) {
		t.Parallel()

		now := time.Now()
		tok, err := jwt.NewBuilder().
			IssuedAt(now.Add(-2 * time.Hour)).
			Expiration(now.Add(1 * time.Hour)).
			NotBefore(now.Add(-2 * time.Hour)).
			Build()
		require.NoError(t, err)

		// exp - iat > 1h (it's 3h), so MaxDeltaIs should fail
		err = jwt.Validate(tok,
			jwt.WithValidator(jwt.MaxDeltaIs(jwt.ExpirationKey, jwt.IssuedAtKey, time.Hour)),
		)
		require.Error(t, err)

		deltaErr, ok := errors.AsType[jwt.TimeDeltaError](err)
		require.True(t, ok, "errors.AsType should find TimeDeltaError")
		require.Equal(t, jwt.ExpirationKey, deltaErr.Claim1)
		require.Equal(t, jwt.IssuedAtKey, deltaErr.Claim2)
		require.Greater(t, deltaErr.Delta, time.Hour, "delta should exceed limit")
		require.Equal(t, time.Hour, deltaErr.Limit)
	})
}

func TestCollectErrors(t *testing.T) {
	t.Parallel()

	t.Run("default returns first error only", func(t *testing.T) {
		t.Parallel()

		tok, err := jwt.NewBuilder().
			Issuer("wrong").
			Expiration(time.Now().Add(-1 * time.Hour)).
			Build()
		require.NoError(t, err)

		err = jwt.Validate(tok, jwt.WithIssuer("expected"))
		require.Error(t, err)
		require.ErrorIs(t, err, jwt.ValidationError{})
		require.ErrorIs(t, err, jwt.TokenExpiredError{})
	})

	t.Run("WithCollectErrors returns all errors", func(t *testing.T) {
		t.Parallel()

		tok, err := jwt.NewBuilder().
			Issuer("wrong").
			Expiration(time.Now().Add(-1 * time.Hour)).
			Build()
		require.NoError(t, err)

		err = jwt.Validate(tok,
			jwt.WithIssuer("expected"),
			jwt.WithCollectErrors(true),
		)
		require.Error(t, err)
		require.ErrorIs(t, err, jwt.ValidationError{})

		// Both errors should be present
		require.ErrorIs(t, err, jwt.TokenExpiredError{})
		require.ErrorIs(t, err, jwt.InvalidIssuerError{})

		// Structured fields should still be accessible
		expErr, ok := errors.AsType[jwt.TokenExpiredError](err)
		require.True(t, ok, "errors.AsType should work on collected errors")
		require.False(t, expErr.Expiration.IsZero())
	})

	t.Run("WithCollectErrors(false) behaves like default", func(t *testing.T) {
		t.Parallel()

		tok, err := jwt.NewBuilder().
			Issuer("wrong").
			Expiration(time.Now().Add(-1 * time.Hour)).
			Build()
		require.NoError(t, err)

		err = jwt.Validate(tok,
			jwt.WithIssuer("expected"),
			jwt.WithCollectErrors(false),
		)
		require.Error(t, err)

		require.ErrorIs(t, err, jwt.TokenExpiredError{})
		require.False(t, errors.Is(err, jwt.InvalidIssuerError{}))
	})

	t.Run("no errors still returns nil", func(t *testing.T) {
		t.Parallel()

		tok, err := jwt.NewBuilder().
			Issuer("correct").
			Expiration(time.Now().Add(1 * time.Hour)).
			Build()
		require.NoError(t, err)

		err = jwt.Validate(tok,
			jwt.WithIssuer("correct"),
			jwt.WithCollectErrors(true),
		)
		require.NoError(t, err)
	})

	t.Run("Get returns ClaimNotFoundError when claim is missing", func(t *testing.T) {
		t.Parallel()

		tok, err := jwt.NewBuilder().Issuer("me").Build()
		require.NoError(t, err)

		_, err = jwt.Get[string](tok, "absent")
		require.Error(t, err)
		require.ErrorContains(t, err, `jwt.Get`)
		require.ErrorIs(t, err, jwt.ClaimNotFoundError{})
		require.False(t, errors.Is(err, jwt.ClaimTypeMismatchError{}))

		notFound, ok := errors.AsType[jwt.ClaimNotFoundError](err)
		require.True(t, ok, `errors.AsType should find ClaimNotFoundError`)
		require.Equal(t, `absent`, notFound.Name)
	})

	t.Run("Get returns ClaimTypeMismatchError when claim is wrong type", func(t *testing.T) {
		t.Parallel()

		tok, err := jwt.NewBuilder().Issuer("me").Build()
		require.NoError(t, err)

		_, err = jwt.Get[int](tok, jwt.IssuerKey)
		require.Error(t, err)
		require.ErrorContains(t, err, `jwt.Get`)
		require.ErrorIs(t, err, jwt.ClaimTypeMismatchError{})
		require.False(t, errors.Is(err, jwt.ClaimNotFoundError{}))

		mismatch, ok := errors.AsType[jwt.ClaimTypeMismatchError](err)
		require.True(t, ok, `errors.AsType should find ClaimTypeMismatchError`)
		require.Equal(t, jwt.IssuerKey, mismatch.Name)
		require.IsType(t, "", mismatch.Got, `Got should carry the stored string value`)
		require.IsType(t, 0, mismatch.Want, `Want should carry a zero int`)
	})
}
