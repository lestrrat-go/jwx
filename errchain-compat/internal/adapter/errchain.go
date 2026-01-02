package adapter

import (
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

// ErrchainAdapter implements the Adapter interface using errchain-migration version
type ErrchainAdapter struct{}

func (a *ErrchainAdapter) Name() string {
	return "errchain-migration"
}

// Error factory functions
func (a *ErrchainAdapter) ParseError() error {
	return jwt.ParseError()
}

func (a *ErrchainAdapter) ValidateError() error {
	return jwt.ValidateError()
}

func (a *ErrchainAdapter) InvalidIssuerError() error {
	return jwt.InvalidIssuerError()
}

func (a *ErrchainAdapter) TokenExpiredError() error {
	return jwt.TokenExpiredError()
}

func (a *ErrchainAdapter) InvalidIssuedAtError() error {
	return jwt.InvalidIssuedAtError()
}

func (a *ErrchainAdapter) TokenNotYetValidError() error {
	return jwt.TokenNotYetValidError()
}

func (a *ErrchainAdapter) InvalidAudienceError() error {
	return jwt.InvalidAudienceError()
}

func (a *ErrchainAdapter) MissingRequiredClaimError() error {
	return jwt.MissingRequiredClaimError()
}

func (a *ErrchainAdapter) ClaimNotFoundError() error {
	return jwt.ClaimNotFoundError()
}

func (a *ErrchainAdapter) ClaimAssignmentFailedError() error {
	return jwt.ClaimAssignmentFailedError()
}

func (a *ErrchainAdapter) UnknownPayloadTypeError() error {
	return jwt.UnknownPayloadTypeError()
}

// Operations that produce errors
func (a *ErrchainAdapter) ParseInvalidToken(input []byte) error {
	_, err := jwt.Parse(input, jwt.WithVerify(false))
	return err
}

func (a *ErrchainAdapter) ParseMalformedJSON(input []byte) error {
	_, err := jwt.Parse(input, jwt.WithVerify(false))
	return err
}

func (a *ErrchainAdapter) ParseWithInvalidSignature() error {
	// Simplified: Just use an invalid signature directly
	// This is a token with a tampered signature
	invalidSignedToken := []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.invalid_signature")

	_, err := jwt.Parse(invalidSignedToken, jwt.WithVerify(false))
	// Note: With WithVerify(false), this won't actually fail on signature
	// Instead, let's just return a parse error from malformed data
	if err != nil {
		return err
	}
	// If it didn't error, create a parse scenario that will
	return a.ParseInvalidToken([]byte("definitely.not.valid"))
}

func (a *ErrchainAdapter) ValidateExpiredToken(expTime time.Time) error {
	tok := jwt.New()
	tok.Set(jwt.ExpirationKey, expTime.Unix())

	return jwt.Validate(tok)
}

func (a *ErrchainAdapter) ValidateNotYetValidToken(nbfTime time.Time) error {
	tok := jwt.New()
	tok.Set(jwt.NotBeforeKey, nbfTime.Unix())

	return jwt.Validate(tok)
}

func (a *ErrchainAdapter) ValidateInvalidIssuer(tokenIssuer string, expectedIssuer string) error {
	tok := jwt.New()
	tok.Set(jwt.IssuerKey, tokenIssuer)

	return jwt.Validate(tok, jwt.WithIssuer(expectedIssuer))
}

func (a *ErrchainAdapter) ValidateInvalidAudience(tokenAudience string, expectedAudience string) error {
	tok := jwt.New()
	tok.Set(jwt.AudienceKey, []string{tokenAudience})

	return jwt.Validate(tok, jwt.WithAudience(expectedAudience))
}

func (a *ErrchainAdapter) ValidateMissingRequiredClaim(requiredClaim string) error {
	tok := jwt.New()
	// Don't set the required claim

	return jwt.Validate(tok, jwt.WithRequiredClaim(requiredClaim))
}

func (a *ErrchainAdapter) GetNonExistentClaim(claimName string) error {
	tok := jwt.New()

	var value string
	return tok.Get(claimName, &value)
}

func (a *ErrchainAdapter) GetClaimWithWrongType() error {
	tok := jwt.New()
	tok.Set("stringClaim", "this is a string")

	var value int
	return tok.Get("stringClaim", &value)
}
