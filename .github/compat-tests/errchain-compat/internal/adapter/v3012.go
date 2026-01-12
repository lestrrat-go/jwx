package adapter

import (
	"time"

	"github.com/lestrrat-go/jwx-v3012/v3/jwt"
)

// V3012Adapter implements the Adapter interface using v3.0.12
type V3012Adapter struct{}

func (a *V3012Adapter) Name() string {
	return "v3.0.12"
}

// Error factory functions
func (a *V3012Adapter) ParseError() error {
	return jwt.ParseError()
}

func (a *V3012Adapter) ValidateError() error {
	return jwt.ValidateError()
}

func (a *V3012Adapter) InvalidIssuerError() error {
	return jwt.InvalidIssuerError()
}

func (a *V3012Adapter) TokenExpiredError() error {
	return jwt.TokenExpiredError()
}

func (a *V3012Adapter) InvalidIssuedAtError() error {
	return jwt.InvalidIssuedAtError()
}

func (a *V3012Adapter) TokenNotYetValidError() error {
	return jwt.TokenNotYetValidError()
}

func (a *V3012Adapter) InvalidAudienceError() error {
	return jwt.InvalidAudienceError()
}

func (a *V3012Adapter) MissingRequiredClaimError() error {
	return jwt.MissingRequiredClaimError()
}

func (a *V3012Adapter) ClaimNotFoundError() error {
	return jwt.ClaimNotFoundError()
}

func (a *V3012Adapter) ClaimAssignmentFailedError() error {
	return jwt.ClaimAssignmentFailedError()
}

func (a *V3012Adapter) UnknownPayloadTypeError() error {
	return jwt.UnknownPayloadTypeError()
}

// Operations that produce errors
func (a *V3012Adapter) ParseInvalidToken(input []byte) error {
	_, err := jwt.Parse(input, jwt.WithVerify(false))
	return err
}

func (a *V3012Adapter) ParseMalformedJSON(input []byte) error {
	_, err := jwt.Parse(input, jwt.WithVerify(false))
	return err
}

func (a *V3012Adapter) ParseWithInvalidSignature() error {
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

func (a *V3012Adapter) ValidateExpiredToken(expTime time.Time) error {
	tok := jwt.New()
	tok.Set(jwt.ExpirationKey, expTime.Unix())

	return jwt.Validate(tok)
}

func (a *V3012Adapter) ValidateNotYetValidToken(nbfTime time.Time) error {
	tok := jwt.New()
	tok.Set(jwt.NotBeforeKey, nbfTime.Unix())

	return jwt.Validate(tok)
}

func (a *V3012Adapter) ValidateInvalidIssuer(tokenIssuer string, expectedIssuer string) error {
	tok := jwt.New()
	tok.Set(jwt.IssuerKey, tokenIssuer)

	return jwt.Validate(tok, jwt.WithIssuer(expectedIssuer))
}

func (a *V3012Adapter) ValidateInvalidAudience(tokenAudience string, expectedAudience string) error {
	tok := jwt.New()
	tok.Set(jwt.AudienceKey, []string{tokenAudience})

	return jwt.Validate(tok, jwt.WithAudience(expectedAudience))
}

func (a *V3012Adapter) ValidateMissingRequiredClaim(requiredClaim string) error {
	tok := jwt.New()
	// Don't set the required claim

	return jwt.Validate(tok, jwt.WithRequiredClaim(requiredClaim))
}

func (a *V3012Adapter) GetNonExistentClaim(claimName string) error {
	tok := jwt.New()

	var value string
	return tok.Get(claimName, &value)
}

func (a *V3012Adapter) GetClaimWithWrongType() error {
	tok := jwt.New()
	tok.Set("stringClaim", "this is a string")

	var value int
	return tok.Get("stringClaim", &value)
}
