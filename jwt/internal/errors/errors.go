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

// Error prefixes for ErrFromParse calls
const (
	PrefixParse              = "jwt.Parse"
	PrefixParseCookie        = "jwt.ParseCookie"
	PrefixParseForm          = "jwt.ParseForm"
	PrefixParseHeader        = "jwt.ParseHeader"
	PrefixParseRequest       = "jwt.ParseRequest"
	PrefixSerialize          = "jwt.Serialize"
	PrefixSerializerEncrypt  = "jwt.Serializer.Encrypt"
	PrefixSerializerSign     = "jwt.Serializer.Sign"
	PrefixTokenUnmarshalJSON = "jwt.Token.UnmarshalJSON"
	PrefixParseInsecure      = "jwt.ParseInsecure"
	PrefixParseReader        = "jwt.ParseReader"
	PrefixParseString        = "jwt.ParseString"
	PrefixClone              = "jwt.Clone"
	PrefixSign               = "jwt.Sign"
	PrefixOpenIDClone        = "openid.Clone"
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

// ErrFromParse creates a ParseError by wrapping an error with context using errchain.
// The prefix is the operation name (e.g., "jwt.Parse"), and the format string and args
// are used to create the error message. Supports %w verb for error wrapping.
//
// The error chain is preserved intact. errchain's Concise mode will hide intermediate
// messages by default, but Verbose mode (%+v) will show the full chain.
//
// Example:
//
//	ErrFromParse("jwt.Parse", "failed to parse token: %w", innerErr)
//	-> Concise: "jwt.Parse: <innerErr message>"
//	-> Verbose: "jwt.Parse: failed to parse token: <innerErr message>"
func ErrFromParse(prefix, f string, args ...any) error {
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

// ErrFromValidate creates a ValidationError by wrapping an error with context using errchain.
// Supports %w verb for error wrapping.
//
// The error chain is preserved intact. errchain's Concise mode will hide intermediate
// messages by default, but Verbose mode (%+v) will show the full chain.
//
// Example:
//
//	ErrFromValidate("validation failed: %w", expCheckErr)
//	-> Concise: "jwt.Validate: <expCheckErr message>"
//	-> Verbose: "jwt.Validate: validation failed: <expCheckErr message>"
func ErrFromValidate(f string, args ...any) error {
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

// ErrFromIssuer creates an InvalidIssuerError by wrapping an error with context using errchain.
// Supports %w verb for error wrapping.
//
// The error chain is preserved intact. errchain's Concise mode will hide intermediate
// messages by default, but Verbose mode (%+v) will show the full chain.
//
// Example:
//
//	ErrFromIssuer("token issuer mismatch (expected %q, got %q)", expected, actual)
//	-> Concise: "\"iss\" not satisfied: token issuer mismatch (expected X, got Y)"
//	-> Verbose: "\"iss\" not satisfied: token issuer mismatch (expected X, got Y)"
func ErrFromIssuer(f string, args ...any) error {
	innerErr := fmt.Errorf(f, args...)
	return InvalidIssuerError{errchain.Wrap(stderrors.New(`"iss" not satisfied`), innerErr)}
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

// ErrFromTokenExpired creates a TokenExpiredError by wrapping an error with context using errchain.
// Supports %w verb for error wrapping.
//
// The error chain is preserved intact. errchain's Concise mode will hide intermediate
// messages by default, but Verbose mode (%+v) will show the full chain.
//
// Example:
//
//	ErrFromTokenExpired("token is expired")
//	-> Concise: "\"exp\" not satisfied: token is expired"
//	-> Verbose: "\"exp\" not satisfied: token is expired"
func ErrFromTokenExpired(f string, args ...any) error {
	innerErr := fmt.Errorf(f, args...)
	return TokenExpiredError{errchain.Wrap(stderrors.New(`"exp" not satisfied`), innerErr)}
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

// ErrFromInvalidIssuedAt creates an InvalidIssuedAtError by wrapping an error with context using errchain.
// Supports %w verb for error wrapping.
//
// The error chain is preserved intact. errchain's Concise mode will hide intermediate
// messages by default, but Verbose mode (%+v) will show the full chain.
//
// Example:
//
//	ErrFromInvalidIssuedAt("token was issued in the future")
//	-> Concise: "\"iat\" not satisfied: token was issued in the future"
//	-> Verbose: "\"iat\" not satisfied: token was issued in the future"
func ErrFromInvalidIssuedAt(f string, args ...any) error {
	innerErr := fmt.Errorf(f, args...)
	return InvalidIssuedAtError{errchain.Wrap(stderrors.New(`"iat" not satisfied`), innerErr)}
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

// ErrFromTokenNotYetValid creates a TokenNotYetValidError by wrapping an error with context using errchain.
// Supports %w verb for error wrapping.
//
// The error chain is preserved intact. errchain's Concise mode will hide intermediate
// messages by default, but Verbose mode (%+v) will show the full chain.
//
// Example:
//
//	ErrFromTokenNotYetValid("token not yet valid")
//	-> Concise: "\"nbf\" not satisfied: token not yet valid"
//	-> Verbose: "\"nbf\" not satisfied: token not yet valid"
func ErrFromTokenNotYetValid(f string, args ...any) error {
	innerErr := fmt.Errorf(f, args...)
	return TokenNotYetValidError{errchain.Wrap(stderrors.New(`"nbf" not satisfied`), innerErr)}
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

// ErrFromAudience creates an InvalidAudienceError by wrapping an error with context using errchain.
// Supports %w verb for error wrapping.
//
// The error chain is preserved intact. errchain's Concise mode will hide intermediate
// messages by default, but Verbose mode (%+v) will show the full chain.
//
// Example:
//
//	ErrFromAudience("token audience not found (expected %q)", expected)
//	-> Concise: "\"aud\" not satisfied: token audience not found (expected X)"
//	-> Verbose: "\"aud\" not satisfied: token audience not found (expected X)"
func ErrFromAudience(f string, args ...any) error {
	innerErr := fmt.Errorf(f, args...)
	return InvalidAudienceError{errchain.Wrap(stderrors.New(`"aud" not satisfied`), innerErr)}
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

// ErrFromMissingRequiredClaim creates a MissingRequiredClaimError for the given claim name.
func ErrFromMissingRequiredClaim(name string) error {
	return &MissingRequiredClaimError{claim: name, error: fmt.Errorf(`required claim "%s" is missing`, name)}
}

// ErrFromClaim wraps token claim access errors (used by Token.Set/UnmarshalJSON/MarshalJSON methods)
func ErrFromClaim(f string, args ...any) error {
	innerErr := fmt.Errorf(f, args...)
	return errchain.Wrap(stderrors.New("jwt.Token"), innerErr)
}
