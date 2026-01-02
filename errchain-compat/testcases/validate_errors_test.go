package testcases_test

import (
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/compat-tests/internal/adapter"
	"github.com/lestrrat-go/jwx/v3/compat-tests/internal/compare"
	"github.com/stretchr/testify/require"
)

func TestValidationErrors(t *testing.T) {
	v3012 := &adapter.V3012Adapter{}
	errchain := &adapter.ErrchainAdapter{}

	testcases := []struct {
		name            string
		generateError   func(adapter.Adapter) error
		specificError   func(adapter.Adapter) error
		expectedContext string
	}{
		{
			name: "token expired",
			generateError: func(a adapter.Adapter) error {
				return a.ValidateExpiredToken(time.Now().Add(-24 * time.Hour))
			},
			specificError: func(a adapter.Adapter) error {
				return a.TokenExpiredError()
			},
			expectedContext: "jwt.Validate",
		},
		{
			name: "token not yet valid",
			generateError: func(a adapter.Adapter) error {
				return a.ValidateNotYetValidToken(time.Now().Add(24 * time.Hour))
			},
			specificError: func(a adapter.Adapter) error {
				return a.TokenNotYetValidError()
			},
			expectedContext: "jwt.Validate",
		},
		{
			name: "invalid issuer",
			generateError: func(a adapter.Adapter) error {
				return a.ValidateInvalidIssuer("wrong-issuer", "expected-issuer")
			},
			specificError: func(a adapter.Adapter) error {
				return a.InvalidIssuerError()
			},
			expectedContext: "",
		},
		{
			name: "invalid audience",
			generateError: func(a adapter.Adapter) error {
				return a.ValidateInvalidAudience("wrong-audience", "expected-audience")
			},
			specificError: func(a adapter.Adapter) error {
				return a.InvalidAudienceError()
			},
			expectedContext: "",
		},
		{
			name: "missing required claim",
			generateError: func(a adapter.Adapter) error {
				return a.ValidateMissingRequiredClaim("custom-claim")
			},
			specificError: func(a adapter.Adapter) error {
				return a.MissingRequiredClaimError()
			},
			expectedContext: "",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate errors from both versions
			err3012 := tc.generateError(v3012)
			errErrchain := tc.generateError(errchain)

			// Both should produce errors
			require.Error(t, err3012, "v3.0.12 should produce an error")
			require.Error(t, errErrchain, "errchain-migration should produce an error")

			// Test errors.Is() for ValidateError (parent error type)
			result := compare.CompareErrorIs(tc.name, err3012, errErrchain, v3012.ValidateError())
			require.True(t, result.Passed, "ValidateError compatibility: %s", result.Details)

			// Test errors.Is() for specific error type
			result = compare.CompareErrorIs(tc.name, err3012, errErrchain, tc.specificError(v3012))
			require.True(t, result.Passed, "Specific error type compatibility: %s", result.Details)

			// Test errors.Unwrap() behavior
			result = compare.CompareUnwrap(tc.name, err3012, errErrchain)
			require.True(t, result.Passed, "Unwrap compatibility: %s", result.Details)

			// Test message semantics (if context is expected)
			if tc.expectedContext != "" {
				result = compare.CompareMessageSemantics(tc.name, err3012, errErrchain, tc.expectedContext)
				require.True(t, result.Passed, "Message semantics: %s\n  v3.0.12: %s\n  errchain: %s",
					result.Details, result.V3012Value, result.ErrchainValue)
			}
		})
	}
}

func TestValidationError_ErrorTypeMatching(t *testing.T) {
	v3012 := &adapter.V3012Adapter{}
	errchain := &adapter.ErrchainAdapter{}

	t.Run("TokenExpiredError", func(t *testing.T) {
		err3012 := v3012.ValidateExpiredToken(time.Now().Add(-24 * time.Hour))
		errErrchain := errchain.ValidateExpiredToken(time.Now().Add(-24 * time.Hour))

		// Should match TokenExpiredError
		result := compare.CompareErrorIs("TokenExpiredError match", err3012, errErrchain, v3012.TokenExpiredError())
		require.True(t, result.Passed, result.Details)

		// Should match parent ValidateError
		result = compare.CompareErrorIs("ValidateError match", err3012, errErrchain, v3012.ValidateError())
		require.True(t, result.Passed, result.Details)

		// Should not match other validation errors
		result = compare.CompareErrorIs("TokenNotYetValidError non-match", err3012, errErrchain, v3012.TokenNotYetValidError())
		require.True(t, result.Passed, result.Details)

		result = compare.CompareErrorIs("InvalidIssuerError non-match", err3012, errErrchain, v3012.InvalidIssuerError())
		require.True(t, result.Passed, result.Details)
	})

	t.Run("TokenNotYetValidError", func(t *testing.T) {
		err3012 := v3012.ValidateNotYetValidToken(time.Now().Add(24 * time.Hour))
		errErrchain := errchain.ValidateNotYetValidToken(time.Now().Add(24 * time.Hour))

		// Should match TokenNotYetValidError
		result := compare.CompareErrorIs("TokenNotYetValidError match", err3012, errErrchain, v3012.TokenNotYetValidError())
		require.True(t, result.Passed, result.Details)

		// Should match parent ValidateError
		result = compare.CompareErrorIs("ValidateError match", err3012, errErrchain, v3012.ValidateError())
		require.True(t, result.Passed, result.Details)

		// Should not match other validation errors
		result = compare.CompareErrorIs("TokenExpiredError non-match", err3012, errErrchain, v3012.TokenExpiredError())
		require.True(t, result.Passed, result.Details)
	})

	t.Run("InvalidIssuerError", func(t *testing.T) {
		err3012 := v3012.ValidateInvalidIssuer("wrong", "expected")
		errErrchain := errchain.ValidateInvalidIssuer("wrong", "expected")

		// Should match InvalidIssuerError
		result := compare.CompareErrorIs("InvalidIssuerError match", err3012, errErrchain, v3012.InvalidIssuerError())
		require.True(t, result.Passed, result.Details)

		// Should match parent ValidateError
		result = compare.CompareErrorIs("ValidateError match", err3012, errErrchain, v3012.ValidateError())
		require.True(t, result.Passed, result.Details)
	})

	t.Run("InvalidAudienceError", func(t *testing.T) {
		err3012 := v3012.ValidateInvalidAudience("wrong", "expected")
		errErrchain := errchain.ValidateInvalidAudience("wrong", "expected")

		// Should match InvalidAudienceError
		result := compare.CompareErrorIs("InvalidAudienceError match", err3012, errErrchain, v3012.InvalidAudienceError())
		require.True(t, result.Passed, result.Details)

		// Should match parent ValidateError
		result = compare.CompareErrorIs("ValidateError match", err3012, errErrchain, v3012.ValidateError())
		require.True(t, result.Passed, result.Details)
	})

	t.Run("MissingRequiredClaimError", func(t *testing.T) {
		err3012 := v3012.ValidateMissingRequiredClaim("custom-claim")
		errErrchain := errchain.ValidateMissingRequiredClaim("custom-claim")

		// Should match MissingRequiredClaimError
		result := compare.CompareErrorIs("MissingRequiredClaimError match", err3012, errErrchain, v3012.MissingRequiredClaimError())
		require.True(t, result.Passed, result.Details)

		// Should match parent ValidateError
		result = compare.CompareErrorIs("ValidateError match", err3012, errErrchain, v3012.ValidateError())
		require.True(t, result.Passed, result.Details)
	})
}
