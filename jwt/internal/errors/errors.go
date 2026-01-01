// Package errors exist to store errors for jwt and openid packages.
//
// It's internal because we don't want to expose _anything_ about these errors
// so users absolutely cannot do anything other than use them as opaque errors.
package errors

import (
	stderrors "errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/internal/errchain"
)

var (
	ErrClaimNotFound               = ClaimNotFoundError{}
	ErrClaimAssignmentFailed       = ClaimAssignmentFailedError{Err: stderrors.New(`claim assignment failed`)}
	ErrUnknownPayloadType          = stderrors.New(`unknown payload type (payload is not JWT?)`)
	ErrParse                       = ParseError{error: stderrors.New(`jwt.Parse: unknown error`)}
	ErrValidateDefault             = ValidationError{stderrors.New(`unknown error`)}
	ErrInvalidIssuerDefault        = InvalidIssuerError{stderrors.New(`"iss" not satisfied`)}
	ErrTokenExpiredDefault         = TokenExpiredError{stderrors.New(`"exp" not satisfied: token is expired`)}
	ErrInvalidIssuedAtDefault      = InvalidIssuedAtError{stderrors.New(`"iat" not satisfied`)}
	ErrTokenNotYetValidDefault     = TokenNotYetValidError{stderrors.New(`"nbf" not satisfied: token is not yet valid`)}
	ErrInvalidAudienceDefault      = InvalidAudienceError{stderrors.New(`"aud" not satisfied`)}
	ErrMissingRequiredClaimDefault = &MissingRequiredClaimError{error: stderrors.New(`required claim is missing`)}
)

type ClaimNotFoundError struct {
	Name string
}

func (e ClaimNotFoundError) Error() string {
	// This error message uses "field" instead of "claim" for backwards compatibility,
	// but it shuold really be "claim" since it refers to a JWT claim.
	return fmt.Sprintf(`field "%s" not found`, e.Name)
}

func (e ClaimNotFoundError) Is(target error) bool {
	_, ok := target.(ClaimNotFoundError)
	return ok
}

type ClaimAssignmentFailedError struct {
	Err error
}

func (e ClaimAssignmentFailedError) Error() string {
	// This error message probably should be tweaked, but it is this way
	// for backwards compatibility.
	return fmt.Sprintf(`failed to assign value to dst: %s`, e.Err.Error())
}

func (e ClaimAssignmentFailedError) Unwrap() error {
	return e.Err
}

func (e ClaimAssignmentFailedError) Is(target error) bool {
	_, ok := target.(ClaimAssignmentFailedError)
	return ok
}

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

// ParseErrorf creates a ParseError by wrapping an error with context using errchain.
// The prefix is the operation name (e.g., "jwt.Parse"), and the format string and args
// are used to create the error message. Supports %w verb for error wrapping.
//
// The error chain is preserved intact. errchain's Concise mode will hide intermediate
// messages by default, but Verbose mode (%+v) will show the full chain.
//
// Example:
//
//	ParseErrorf("jwt.Parse", "failed to parse token: %w", innerErr)
//	-> Concise: "jwt.Parse: <innerErr message>"
//	-> Verbose: "jwt.Parse: failed to parse token: <innerErr message>"
func ParseErrorf(prefix, f string, args ...any) error {
	// Use fmt.Errorf to properly handle %w and create the wrapped error
	innerErr := fmt.Errorf(f, args...)

	// Wrap the prefix with the full formatted error (preserving developer's message)
	return ParseError{errchain.Wrap(stderrors.New(prefix), innerErr)}
}

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

// ValidateErrorf creates a ValidationError by wrapping an error with context using errchain.
// Supports %w verb for error wrapping.
//
// The error chain is preserved intact. errchain's Concise mode will hide intermediate
// messages by default, but Verbose mode (%+v) will show the full chain.
//
// Example:
//
//	ValidateErrorf("validation failed: %w", expCheckErr)
//	-> Concise: "jwt.Validate: <expCheckErr message>"
//	-> Verbose: "jwt.Validate: validation failed: <expCheckErr message>"
func ValidateErrorf(f string, args ...any) error {
	// Use fmt.Errorf to properly handle %w and create the wrapped error
	innerErr := fmt.Errorf(f, args...)

	// Wrap with the full formatted error (preserving developer's message)
	return ValidationError{errchain.Wrap(stderrors.New("jwt.Validate"), innerErr)}
}

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

// IssuerErrorf creates an InvalidIssuerError with the given format and args.
func IssuerErrorf(f string, args ...any) error {
	return InvalidIssuerError{stderrors.New(`"iss" not satisfied: ` + fmt.Sprintf(f, args...))}
}

type TokenExpiredError struct {
	error
}

func (err TokenExpiredError) Is(target error) bool {
	_, ok := target.(TokenExpiredError)
	return ok
}

func (err TokenExpiredError) Unwrap() error {
	return err.error
}

type InvalidIssuedAtError struct {
	error
}

func (err InvalidIssuedAtError) Is(target error) bool {
	_, ok := target.(InvalidIssuedAtError)
	return ok
}

func (err InvalidIssuedAtError) Unwrap() error {
	return err.error
}

type TokenNotYetValidError struct {
	error
}

func (err TokenNotYetValidError) Is(target error) bool {
	_, ok := target.(TokenNotYetValidError)
	return ok
}

func (err TokenNotYetValidError) Unwrap() error {
	return err.error
}

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

// AudienceErrorf creates an InvalidAudienceError with the given format and args.
func AudienceErrorf(f string, args ...any) error {
	return InvalidAudienceError{stderrors.New(`"aud" not satisfied: ` + fmt.Sprintf(f, args...))}
}

type MissingRequiredClaimError struct {
	error

	claim string
}

func (err *MissingRequiredClaimError) Is(target error) bool {
	err1, ok := target.(*MissingRequiredClaimError)
	if !ok {
		return false
	}
	return err1 == ErrMissingRequiredClaimDefault || err1.claim == err.claim
}

// MissingRequiredClaimErrorf creates a MissingRequiredClaimError for the given claim name.
func MissingRequiredClaimErrorf(name string) error {
	return &MissingRequiredClaimError{claim: name, error: fmt.Errorf(`required claim "%s" is missing`, name)}
}
