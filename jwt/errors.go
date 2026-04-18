package jwt

import (
	"errors"
	"fmt"
	"time"
)

// errUnknownPayloadType is the sentinel for unknown payload type errors.
var errUnknownPayloadType = errors.New(`unknown payload type (payload is not JWT?)`)

// UnknownPayloadTypeError returns the opaque error value that is returned when
// jwt.Parse fails due to not being able to deduce the format of
// the incoming buffer.
//
// This value should only be used for comparison using errors.Is().
func UnknownPayloadTypeError() error {
	return errUnknownPayloadType
}

//-------------------------------------------------------------------
// ClaimNotFoundError
//-------------------------------------------------------------------

// ClaimNotFoundError is returned when jwt.Get fails to find the requested claim.
type ClaimNotFoundError struct {
	// Name is the name of the claim that was not found.
	Name string
}

func (e ClaimNotFoundError) Error() string {
	return fmt.Sprintf(`field "%s" not found`, e.Name)
}

func (e ClaimNotFoundError) Is(target error) bool {
	_, ok := target.(ClaimNotFoundError)
	return ok
}

//-------------------------------------------------------------------
// ClaimTypeMismatchError
//-------------------------------------------------------------------

// ClaimTypeMismatchError is returned when jwt.Get finds the requested
// claim but the stored value cannot be converted to the requested type.
//
// Callers that need to distinguish "claim missing" from "claim present
// but wrong type" should use errors.Is with ClaimNotFoundError{} /
// ClaimTypeMismatchError{}, or errors.AsType to recover the Name, Got,
// and Want fields.
type ClaimTypeMismatchError struct {
	// Name is the name of the claim whose value could not be converted.
	Name string
	// Got is the value currently stored under the claim. Use %T to
	// inspect its concrete type.
	Got any
	// Want is a zero value of the requested type T. Use %T to inspect
	// its concrete type.
	Want any
}

func (e ClaimTypeMismatchError) Error() string {
	return fmt.Sprintf(`field "%s" is %T, not %T`, e.Name, e.Got, e.Want)
}

func (e ClaimTypeMismatchError) Is(target error) bool {
	_, ok := target.(ClaimTypeMismatchError)
	return ok
}

//-------------------------------------------------------------------
// ClaimAssignmentFailedError
//-------------------------------------------------------------------

// ClaimAssignmentFailedError is returned when jwt.Get fails to assign
// the value to the destination.
type ClaimAssignmentFailedError struct {
	// Err is the underlying error.
	Err error
}

func (e ClaimAssignmentFailedError) Error() string {
	return fmt.Sprintf(`failed to assign value to dst: %s`, e.Err.Error())
}

func (e ClaimAssignmentFailedError) Unwrap() error {
	return e.Err
}

func (e ClaimAssignmentFailedError) Is(target error) bool {
	_, ok := target.(ClaimAssignmentFailedError)
	return ok
}

//-------------------------------------------------------------------
// ParseError
//-------------------------------------------------------------------

// ParseError is returned when jwt.Parse fails.
type ParseError struct {
	error
}

func (e ParseError) Unwrap() error {
	return e.error
}

func (ParseError) Is(err error) bool {
	_, ok := err.(ParseError)
	return ok
}

func parseErrorf(prefix, f string, args ...any) error {
	return ParseError{fmt.Errorf(prefix+": "+f, args...)}
}

//-------------------------------------------------------------------
// ValidationError
//-------------------------------------------------------------------

// ValidationError is the blanket error returned by jwt.Validate.
// It wraps the specific validation failure(s).
type ValidationError struct {
	error
}

func (ValidationError) Is(err error) bool {
	_, ok := err.(ValidationError)
	return ok
}

func (err ValidationError) Unwrap() error {
	return err.error
}

func validateErrorf(f string, args ...any) error {
	return ValidationError{fmt.Errorf(`jwt.Validate: `+f, args...)}
}

func validateErrorJoin(errs ...error) error {
	return ValidationError{fmt.Errorf("jwt.Validate: validation failed: %w", errors.Join(errs...))}
}

//-------------------------------------------------------------------
// InvalidIssuerError
//-------------------------------------------------------------------

// InvalidIssuerError is returned when the iss claim is not satisfied.
type InvalidIssuerError struct {
	error
}

func (err InvalidIssuerError) Is(target error) bool {
	_, ok := target.(InvalidIssuerError)
	return ok
}

func (err InvalidIssuerError) Unwrap() error {
	return err.error
}

func issuerErrorf(f string, args ...any) error {
	return InvalidIssuerError{fmt.Errorf(`"iss" not satisfied: `+f, args...)}
}

//-------------------------------------------------------------------
// TokenExpiredError
//-------------------------------------------------------------------

// TokenExpiredError is returned when the exp claim is not satisfied.
// The structured fields allow callers to inspect what values were
// compared without re-parsing the token.
type TokenExpiredError struct {
	error

	// Expiration is the token's exp claim value (after truncation).
	Expiration time.Time
	// Now is the time used for comparison (after truncation).
	Now time.Time
	// Skew is the acceptable skew duration.
	Skew time.Duration
}

func (err TokenExpiredError) Is(target error) bool {
	_, ok := target.(TokenExpiredError)
	return ok
}

func (err TokenExpiredError) Unwrap() error {
	return err.error
}

func newTokenExpiredError(expiration, now time.Time, skew time.Duration) error {
	return TokenExpiredError{
		error:      errors.New(`"exp" not satisfied: token is expired`),
		Expiration: expiration,
		Now:        now,
		Skew:       skew,
	}
}

//-------------------------------------------------------------------
// InvalidIssuedAtError
//-------------------------------------------------------------------

// InvalidIssuedAtError is returned when the iat claim is not satisfied.
type InvalidIssuedAtError struct {
	error

	// IssuedAt is the token's iat claim value (after truncation).
	IssuedAt time.Time
	// Now is the time used for comparison (after truncation).
	Now time.Time
	// Skew is the acceptable skew duration.
	Skew time.Duration
}

func (err InvalidIssuedAtError) Is(target error) bool {
	_, ok := target.(InvalidIssuedAtError)
	return ok
}

func (err InvalidIssuedAtError) Unwrap() error {
	return err.error
}

func newInvalidIssuedAtError(issuedAt, now time.Time, skew time.Duration) error {
	return InvalidIssuedAtError{
		error:    errors.New(`"iat" not satisfied`),
		IssuedAt: issuedAt,
		Now:      now,
		Skew:     skew,
	}
}

//-------------------------------------------------------------------
// TokenNotYetValidError
//-------------------------------------------------------------------

// TokenNotYetValidError is returned when the nbf claim is not satisfied.
type TokenNotYetValidError struct {
	error

	// NotBefore is the token's nbf claim value (after truncation).
	NotBefore time.Time
	// Now is the time used for comparison (after truncation).
	Now time.Time
	// Skew is the acceptable skew duration.
	Skew time.Duration
}

func (err TokenNotYetValidError) Is(target error) bool {
	_, ok := target.(TokenNotYetValidError)
	return ok
}

func (err TokenNotYetValidError) Unwrap() error {
	return err.error
}

func newTokenNotYetValidError(notBefore, now time.Time, skew time.Duration) error {
	return TokenNotYetValidError{
		error:     errors.New(`"nbf" not satisfied: token is not yet valid`),
		NotBefore: notBefore,
		Now:       now,
		Skew:      skew,
	}
}

//-------------------------------------------------------------------
// InvalidAudienceError
//-------------------------------------------------------------------

// InvalidAudienceError is returned when the aud claim is not satisfied.
type InvalidAudienceError struct {
	error
}

func (err InvalidAudienceError) Is(target error) bool {
	_, ok := target.(InvalidAudienceError)
	return ok
}

func (err InvalidAudienceError) Unwrap() error {
	return err.error
}

func audienceErrorf(f string, args ...any) error {
	return InvalidAudienceError{fmt.Errorf(`"aud" not satisfied: `+f, args...)}
}

//-------------------------------------------------------------------
// MissingRequiredClaimError
//-------------------------------------------------------------------

// MissingRequiredClaimError is returned when a required claim is missing.
type MissingRequiredClaimError struct {
	error

	// Claim is the name of the missing required claim.
	Claim string
}

func (err MissingRequiredClaimError) Is(target error) bool {
	switch target.(type) {
	case MissingRequiredClaimError, *MissingRequiredClaimError:
		return true
	default:
		return false
	}
}

func (err MissingRequiredClaimError) Unwrap() error {
	return err.error
}

func missingRequiredClaimErrorf(name string) error {
	return MissingRequiredClaimError{Claim: name, error: fmt.Errorf(`required claim "%s" is missing`, name)}
}

//-------------------------------------------------------------------
// ClaimValidationError
//-------------------------------------------------------------------

// ClaimValidationError is returned when a generic claim validator
// (ClaimValueIs, ClaimContainsString) detects a mismatch.
//
// The Error() message intentionally omits the Expected and Actual
// values so that arbitrary claim payloads do not end up in log output
// via "%v"/"%s" formatting. Callers that need to inspect the mismatched
// values can access the fields directly, but should treat them as
// potentially sensitive (PII, secrets, etc.) and avoid logging them
// verbatim.
type ClaimValidationError struct {
	error

	// Claim is the name of the claim that failed validation.
	Claim string
	// Expected is the value the validator expected. May contain
	// sensitive data; see the type-level godoc.
	Expected any
	// Actual is the value found in the token. May contain sensitive
	// data (PII, secrets, etc.); see the type-level godoc.
	Actual any
}

func (err ClaimValidationError) Is(target error) bool {
	_, ok := target.(ClaimValidationError)
	return ok
}

func (err ClaimValidationError) Unwrap() error {
	return err.error
}

func newClaimValidationError(claim string, expected, actual any, msg string) error {
	return ClaimValidationError{
		error:    errors.New(msg),
		Claim:    claim,
		Expected: expected,
		Actual:   actual,
	}
}

//-------------------------------------------------------------------
// TimeDeltaError
//-------------------------------------------------------------------

// TimeDeltaError is returned when a time delta validator
// (MaxDeltaIs, MinDeltaIs) detects that the delta between two
// claims is out of range.
type TimeDeltaError struct {
	error

	// Claim1 is the name of the first claim (or "" for current time).
	Claim1 string
	// Claim2 is the name of the second claim (or "" for current time).
	Claim2 string
	// Value1 is the resolved time value for Claim1.
	Value1 time.Time
	// Value2 is the resolved time value for Claim2.
	Value2 time.Time
	// Delta is the actual duration between Value1 and Value2.
	Delta time.Duration
	// Limit is the threshold duration that was exceeded or not met.
	Limit time.Duration
	// Skew is the acceptable skew duration.
	Skew time.Duration
}

func (err TimeDeltaError) Is(target error) bool {
	_, ok := target.(TimeDeltaError)
	return ok
}

func (err TimeDeltaError) Unwrap() error {
	return err.error
}

func newTimeDeltaError(msg, c1, c2 string, v1, v2 time.Time, delta, limit, skew time.Duration) error {
	return TimeDeltaError{
		error:  errors.New(msg),
		Claim1: c1,
		Claim2: c2,
		Value1: v1,
		Value2: v2,
		Delta:  delta,
		Limit:  limit,
		Skew:   skew,
	}
}
