package adapter

import (
	"time"
)

// Adapter provides a common interface for testing both v3.0.12 and errchain-migration versions
type Adapter interface {
	// Name returns the version name for reporting
	Name() string

	// Error factory functions - return error constants for comparison
	ParseError() error
	ValidateError() error
	InvalidIssuerError() error
	TokenExpiredError() error
	InvalidIssuedAtError() error
	TokenNotYetValidError() error
	InvalidAudienceError() error
	MissingRequiredClaimError() error
	ClaimNotFoundError() error
	ClaimAssignmentFailedError() error
	UnknownPayloadTypeError() error

	// Operations that produce errors - these generate actual errors from various scenarios

	// ParseInvalidToken parses an invalid token and returns the error
	ParseInvalidToken(input []byte) error

	// ParseMalformedJSON parses a token with malformed JSON and returns the error
	ParseMalformedJSON(input []byte) error

	// ParseWithInvalidSignature parses a valid token with wrong signature verification key
	ParseWithInvalidSignature() error

	// ValidateExpiredToken creates and validates an expired token
	ValidateExpiredToken(expTime time.Time) error

	// ValidateNotYetValidToken creates and validates a token with nbf in the future
	ValidateNotYetValidToken(nbfTime time.Time) error

	// ValidateInvalidIssuer creates and validates a token with wrong issuer
	ValidateInvalidIssuer(tokenIssuer string, expectedIssuer string) error

	// ValidateInvalidAudience creates and validates a token with wrong audience
	ValidateInvalidAudience(tokenAudience string, expectedAudience string) error

	// ValidateMissingRequiredClaim validates a token missing a required claim
	ValidateMissingRequiredClaim(requiredClaim string) error

	// GetNonExistentClaim tries to get a claim that doesn't exist
	GetNonExistentClaim(claimName string) error

	// GetClaimWithWrongType tries to get a string claim into an int variable
	GetClaimWithWrongType() error
}
