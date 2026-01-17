package errors_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	jwterrs "github.com/lestrrat-go/jwx/v3/jwt/internal/errors"
	"github.com/stretchr/testify/require"
)

// TestTokenExpiredErrorf tests the TokenExpiredErrorf helper function
func TestTokenExpiredErrorf(t *testing.T) {
	t.Run("errors.Is compatibility", func(t *testing.T) {
		err := jwterrs.ErrFromTokenExpired(`"exp" not satisfied: token is expired (now %d vs exp %d)`, 1000, 900)
		require.True(t, errors.Is(err, jwterrs.ErrTokenExpiredDefault), "errors.Is() broken - should match TokenExpiredError sentinel")
	})

	t.Run("Unwrap", func(t *testing.T) {
		innerErr := errors.New("specific expiration error")
		err := jwterrs.ErrFromTokenExpired(`"exp" not satisfied: token is expired: %w`, innerErr)
		require.True(t, errors.Is(err, innerErr), "Unwrap broken - should find wrapped inner error")
	})

	t.Run("Concise format (%s)", func(t *testing.T) {
		err := jwterrs.ErrFromTokenExpired(`"exp" not satisfied: token is expired (now %d vs exp %d)`, 1000, 900)
		concise := fmt.Sprintf("%s", err)

		require.True(t, strings.Contains(concise, `"exp" not satisfied`), "concise format missing operation context: %s", concise)
		require.True(t, strings.Contains(concise, "token is expired"), "concise format missing root cause: %s", concise)
	})

	t.Run("Verbose format (%+v)", func(t *testing.T) {
		err := jwterrs.ErrFromTokenExpired("outer: %w", fmt.Errorf("middle: %w", errors.New("inner")))
		verbose := fmt.Sprintf("%+v", err)

		require.True(t, strings.Contains(verbose, "outer"), "verbose format missing outer context: %s", verbose)
		require.True(t, strings.Contains(verbose, "middle"), "verbose format missing middle context: %s", verbose)
		require.True(t, strings.Contains(verbose, "inner"), "verbose format missing inner error: %s", verbose)
	})

	t.Run("Verbose shows full chain", func(t *testing.T) {
		err := jwterrs.ErrFromTokenExpired("outer: %w", fmt.Errorf("middle: %w", errors.New("inner")))
		verbose := fmt.Sprintf("%+v", err)

		// Verbose MUST contain all levels of the chain
		require.True(t, strings.Contains(verbose, "outer"), "verbose missing outer: %s", verbose)
		require.True(t, strings.Contains(verbose, "middle"), "verbose missing middle: %s", verbose)
		require.True(t, strings.Contains(verbose, "inner"), "verbose missing inner: %s", verbose)
	})
}

// TestInvalidIssuedAtErrorf tests the InvalidIssuedAtErrorf helper function
func TestInvalidIssuedAtErrorf(t *testing.T) {
	t.Run("errors.Is compatibility", func(t *testing.T) {
		err := jwterrs.ErrFromInvalidIssuedAt(`"iat" not satisfied: token was issued in the future (now %d vs iat %d)`, 1000, 1100)
		require.True(t, errors.Is(err, jwterrs.ErrInvalidIssuedAtDefault), "errors.Is() broken - should match InvalidIssuedAtError sentinel")
	})

	t.Run("Unwrap", func(t *testing.T) {
		innerErr := errors.New("specific iat error")
		err := jwterrs.ErrFromInvalidIssuedAt(`"iat" not satisfied: invalid issued at: %w`, innerErr)
		require.True(t, errors.Is(err, innerErr), "Unwrap broken - should find wrapped inner error")
	})

	t.Run("Concise format (%s)", func(t *testing.T) {
		err := jwterrs.ErrFromInvalidIssuedAt(`"iat" not satisfied: token was issued in the future (now %d vs iat %d)`, 1000, 1100)
		concise := fmt.Sprintf("%s", err)

		require.True(t, strings.Contains(concise, `"iat" not satisfied`), "concise format missing operation context: %s", concise)
		require.True(t, strings.Contains(concise, "token was issued in the future"), "concise format missing root cause: %s", concise)
	})

	t.Run("Verbose format (%+v)", func(t *testing.T) {
		err := jwterrs.ErrFromInvalidIssuedAt("outer: %w", fmt.Errorf("middle: %w", errors.New("inner")))
		verbose := fmt.Sprintf("%+v", err)

		require.True(t, strings.Contains(verbose, "outer"), "verbose format missing outer context: %s", verbose)
		require.True(t, strings.Contains(verbose, "middle"), "verbose format missing middle context: %s", verbose)
		require.True(t, strings.Contains(verbose, "inner"), "verbose format missing inner error: %s", verbose)
	})

	t.Run("Verbose shows full chain", func(t *testing.T) {
		err := jwterrs.ErrFromInvalidIssuedAt("outer: %w", fmt.Errorf("middle: %w", errors.New("inner")))
		verbose := fmt.Sprintf("%+v", err)

		// Verbose MUST contain all levels of the chain
		require.True(t, strings.Contains(verbose, "outer"), "verbose missing outer: %s", verbose)
		require.True(t, strings.Contains(verbose, "middle"), "verbose missing middle: %s", verbose)
		require.True(t, strings.Contains(verbose, "inner"), "verbose missing inner: %s", verbose)
	})
}

// TestTokenNotYetValidErrorf tests the TokenNotYetValidErrorf helper function
func TestTokenNotYetValidErrorf(t *testing.T) {
	t.Run("errors.Is compatibility", func(t *testing.T) {
		err := jwterrs.ErrFromTokenNotYetValid(`"nbf" not satisfied: token not yet valid (now %d vs nbf %d)`, 1000, 1100)
		require.True(t, errors.Is(err, jwterrs.ErrTokenNotYetValidDefault), "errors.Is() broken - should match TokenNotYetValidError sentinel")
	})

	t.Run("Unwrap", func(t *testing.T) {
		innerErr := errors.New("specific nbf error")
		err := jwterrs.ErrFromTokenNotYetValid(`"nbf" not satisfied: not yet valid: %w`, innerErr)
		require.True(t, errors.Is(err, innerErr), "Unwrap broken - should find wrapped inner error")
	})

	t.Run("Concise format (%s)", func(t *testing.T) {
		err := jwterrs.ErrFromTokenNotYetValid(`"nbf" not satisfied: token not yet valid (now %d vs nbf %d)`, 1000, 1100)
		concise := fmt.Sprintf("%s", err)

		require.True(t, strings.Contains(concise, `"nbf" not satisfied`), "concise format missing operation context: %s", concise)
		require.True(t, strings.Contains(concise, "token not yet valid"), "concise format missing root cause: %s", concise)
	})

	t.Run("Verbose format (%+v)", func(t *testing.T) {
		err := jwterrs.ErrFromTokenNotYetValid("outer: %w", fmt.Errorf("middle: %w", errors.New("inner")))
		verbose := fmt.Sprintf("%+v", err)

		require.True(t, strings.Contains(verbose, "outer"), "verbose format missing outer context: %s", verbose)
		require.True(t, strings.Contains(verbose, "middle"), "verbose format missing middle context: %s", verbose)
		require.True(t, strings.Contains(verbose, "inner"), "verbose format missing inner error: %s", verbose)
	})

	t.Run("Verbose shows full chain", func(t *testing.T) {
		err := jwterrs.ErrFromTokenNotYetValid("outer: %w", fmt.Errorf("middle: %w", errors.New("inner")))
		verbose := fmt.Sprintf("%+v", err)

		// Verbose MUST contain all levels of the chain
		require.True(t, strings.Contains(verbose, "outer"), "verbose missing outer: %s", verbose)
		require.True(t, strings.Contains(verbose, "middle"), "verbose missing middle: %s", verbose)
		require.True(t, strings.Contains(verbose, "inner"), "verbose missing inner: %s", verbose)
	})
}

// TestAllValidationErrorsFormatVerbs ensures all validation error types support proper formatting
func TestAllValidationErrorsFormatVerbs(t *testing.T) {
	testCases := []struct {
		name string
		err  error
	}{
		{
			name: "TokenExpiredError",
			err:  jwterrs.ErrFromTokenExpired("outer: %w", fmt.Errorf("middle: %w", errors.New("inner"))),
		},
		{
			name: "InvalidIssuedAtError",
			err:  jwterrs.ErrFromInvalidIssuedAt("outer: %w", fmt.Errorf("middle: %w", errors.New("inner"))),
		},
		{
			name: "TokenNotYetValidError",
			err:  jwterrs.ErrFromTokenNotYetValid("outer: %w", fmt.Errorf("middle: %w", errors.New("inner"))),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			concise := fmt.Sprintf("%s", tc.err)
			verbose := fmt.Sprintf("%+v", tc.err)
			quotedConcise := fmt.Sprintf("%q", tc.err)

			// All formats should produce output
			require.NotEmpty(t, concise, "concise format produced empty string")
			require.NotEmpty(t, verbose, "verbose format produced empty string")
			require.NotEmpty(t, quotedConcise, "quoted format produced empty string")

			// Concise should contain outer and inner
			require.True(t, strings.Contains(concise, "outer"), "concise missing outer context: %s", concise)
			require.True(t, strings.Contains(concise, "inner"), "concise missing inner error: %s", concise)

			// Verbose should contain all levels
			require.True(t, strings.Contains(verbose, "middle"), "verbose missing middle context: %s", verbose)
		})
	}
}

// TestValidationErrorBackwardCompatibility ensures errors.Is() works with sentinel values
func TestValidationErrorBackwardCompatibility(t *testing.T) {
	t.Run("TokenExpiredError sentinel", func(t *testing.T) {
		err := jwterrs.ErrFromTokenExpired("test error")
		require.True(t, errors.Is(err, jwterrs.ErrTokenExpiredDefault), "TokenExpiredError should match sentinel ErrTokenExpiredDefault")
	})

	t.Run("InvalidIssuedAtError sentinel", func(t *testing.T) {
		err := jwterrs.ErrFromInvalidIssuedAt("test error")
		require.True(t, errors.Is(err, jwterrs.ErrInvalidIssuedAtDefault), "InvalidIssuedAtError should match sentinel ErrInvalidIssuedAtDefault")
	})

	t.Run("TokenNotYetValidError sentinel", func(t *testing.T) {
		err := jwterrs.ErrFromTokenNotYetValid("test error")
		require.True(t, errors.Is(err, jwterrs.ErrTokenNotYetValidDefault), "TokenNotYetValidError should match sentinel ErrTokenNotYetValidDefault")
	})
}
