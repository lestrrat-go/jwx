package testcases_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v3/compat-tests/internal/adapter"
	"github.com/lestrrat-go/jwx/v3/compat-tests/internal/compare"
	"github.com/stretchr/testify/require"
)

func TestClaimErrors(t *testing.T) {
	v3012 := &adapter.V3012Adapter{}
	errchain := &adapter.ErrchainAdapter{}

	testcases := []struct {
		name          string
		generateError func(adapter.Adapter) error
		specificError func(adapter.Adapter) error
	}{
		{
			name: "claim not found",
			generateError: func(a adapter.Adapter) error {
				return a.GetNonExistentClaim("nonexistent")
			},
			specificError: func(a adapter.Adapter) error {
				return a.ClaimNotFoundError()
			},
		},
		{
			name: "claim assignment failed (type mismatch)",
			generateError: func(a adapter.Adapter) error {
				return a.GetClaimWithWrongType()
			},
			specificError: func(a adapter.Adapter) error {
				return a.ClaimAssignmentFailedError()
			},
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

			// Test errors.Is() for specific error type
			result := compare.CompareErrorIs(tc.name, err3012, errErrchain, tc.specificError(v3012))
			require.True(t, result.Passed, "Specific error type compatibility: %s", result.Details)

			// Test errors.Unwrap() behavior
			result = compare.CompareUnwrap(tc.name, err3012, errErrchain)
			require.True(t, result.Passed, "Unwrap compatibility: %s", result.Details)
		})
	}
}

func TestClaimNotFoundError_ErrorTypeMatching(t *testing.T) {
	v3012 := &adapter.V3012Adapter{}
	errchain := &adapter.ErrchainAdapter{}

	err3012 := v3012.GetNonExistentClaim("test")
	errErrchain := errchain.GetNonExistentClaim("test")

	t.Run("should match ClaimNotFoundError", func(t *testing.T) {
		result := compare.CompareErrorIs("ClaimNotFoundError match", err3012, errErrchain, v3012.ClaimNotFoundError())
		require.True(t, result.Passed, result.Details)
	})

	t.Run("should not match other error types", func(t *testing.T) {
		otherErrors := []error{
			v3012.ClaimAssignmentFailedError(),
			v3012.ParseError(),
			v3012.ValidateError(),
		}

		for _, otherErr := range otherErrors {
			result := compare.CompareErrorIs("other error non-match", err3012, errErrchain, otherErr)
			require.True(t, result.Passed, "Should not match %T: %s", otherErr, result.Details)
		}
	})
}

func TestClaimAssignmentFailedError_ErrorTypeMatching(t *testing.T) {
	v3012 := &adapter.V3012Adapter{}
	errchain := &adapter.ErrchainAdapter{}

	err3012 := v3012.GetClaimWithWrongType()
	errErrchain := errchain.GetClaimWithWrongType()

	t.Run("should match ClaimAssignmentFailedError", func(t *testing.T) {
		result := compare.CompareErrorIs("ClaimAssignmentFailedError match", err3012, errErrchain, v3012.ClaimAssignmentFailedError())
		require.True(t, result.Passed, result.Details)
	})

	t.Run("should not match other error types", func(t *testing.T) {
		otherErrors := []error{
			v3012.ClaimNotFoundError(),
			v3012.ParseError(),
			v3012.ValidateError(),
		}

		for _, otherErr := range otherErrors {
			result := compare.CompareErrorIs("other error non-match", err3012, errErrchain, otherErr)
			require.True(t, result.Passed, "Should not match %T: %s", otherErr, result.Details)
		}
	})
}
