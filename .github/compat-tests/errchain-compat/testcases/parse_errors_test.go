package testcases_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v3/compat-tests/internal/adapter"
	"github.com/lestrrat-go/jwx/v3/compat-tests/internal/compare"
	"github.com/stretchr/testify/require"
)

func TestParseErrors(t *testing.T) {
	v3012 := &adapter.V3012Adapter{}
	errchain := &adapter.ErrchainAdapter{}

	testcases := []struct {
		name            string
		generateError   func(adapter.Adapter) error
		checkErrorIs    []error
		expectedContext string
	}{
		{
			name: "invalid JWT format",
			generateError: func(a adapter.Adapter) error {
				return a.ParseInvalidToken([]byte("not.a.valid.jwt"))
			},
			checkErrorIs: []error{
				nil, // Will be filled in below with adapter-specific error
			},
			expectedContext: "jwt.Parse",
		},
		{
			name: "malformed JSON payload",
			generateError: func(a adapter.Adapter) error {
				return a.ParseMalformedJSON([]byte("eyJhbGciOiJub25lIn0.{invalid-json}."))
			},
			checkErrorIs: []error{
				nil, // Will be filled in below
			},
			expectedContext: "jwt.Parse",
		},
		{
			name: "invalid signature verification",
			generateError: func(a adapter.Adapter) error {
				return a.ParseWithInvalidSignature()
			},
			checkErrorIs: []error{
				nil, // Will be filled in below
			},
			expectedContext: "jwt.Parse",
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

			// Test errors.Is() for ParseError
			result := compare.CompareErrorIs(tc.name, err3012, errErrchain, v3012.ParseError())
			require.True(t, result.Passed, "ParseError compatibility: %s", result.Details)

			// Test errors.Unwrap() behavior
			result = compare.CompareUnwrap(tc.name, err3012, errErrchain)
			require.True(t, result.Passed, "Unwrap compatibility: %s", result.Details)

			// Test message semantics
			result = compare.CompareMessageSemantics(tc.name, err3012, errErrchain, tc.expectedContext)
			require.True(t, result.Passed, "Message semantics: %s\n  v3.0.12: %s\n  errchain: %s",
				result.Details, result.V3012Value, result.ErrchainValue)
		})
	}
}

func TestParseError_ErrorTypeMatching(t *testing.T) {
	v3012 := &adapter.V3012Adapter{}
	errchain := &adapter.ErrchainAdapter{}

	// Generate a parse error from both versions
	err3012 := v3012.ParseInvalidToken([]byte("invalid"))
	errErrchain := errchain.ParseInvalidToken([]byte("invalid"))

	t.Run("should match ParseError", func(t *testing.T) {
		result := compare.CompareErrorIs("ParseError match", err3012, errErrchain, v3012.ParseError())
		require.True(t, result.Passed, result.Details)
	})

	t.Run("should not match ValidateError", func(t *testing.T) {
		result := compare.CompareErrorIs("ValidateError non-match", err3012, errErrchain, v3012.ValidateError())
		require.True(t, result.Passed, result.Details)
	})

	t.Run("should not match other error types", func(t *testing.T) {
		otherErrors := []error{
			v3012.TokenExpiredError(),
			v3012.InvalidIssuerError(),
			v3012.ClaimNotFoundError(),
		}

		for _, otherErr := range otherErrors {
			result := compare.CompareErrorIs("other error non-match", err3012, errErrchain, otherErr)
			require.True(t, result.Passed, "Should not match %T: %s", otherErr, result.Details)
		}
	})
}
