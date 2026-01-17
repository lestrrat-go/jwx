// Package errors exist to store errors for jwt and openid packages.
//
// It's internal because we don't want to expose _anything_ about these errors
// so users absolutely cannot do anything other than use them as opaque errors.
package errors

import (
	stderrors "errors"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v3/internal/errchain"
)

// Prefix constants for error messages.
// These should be concatenated with ": " and the message description.
//
// Example usage:
//
//	ErrFromParse(PrefixParse + `: failed to parse token: %w`, err)
//
// Always use these constants instead of hardcoded strings for consistency.
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

// removePercentW removes ALL occurrences of %w from the format string
// and cleans up the resulting separators.
//
// This is necessary because errors are extracted separately from args,
// so %w verbs must be removed from the message string before formatting.
//
// Examples:
//
//	"message: %w" → "message"
//	"failed: %w: additional" → "failed: additional"
//	"first: %w and second: %w" → "first: and second" (edge case)
func removePercentW(message string) string {
	result := message

	// Remove ALL occurrences of %w (not just one)
	// Use loop since there could be multiple (though unusual)
	for {
		wIndex := strings.Index(result, "%w")
		if wIndex == -1 {
			break // No more %w found
		}
		// Remove this occurrence
		result = result[:wIndex] + result[wIndex+2:]
	}

	// Collapse multiple consecutive separators that may result from %w removal
	// Example: "failed: %w: text" → "failed: : text" → "failed: text"
	for strings.Contains(result, ": :") {
		result = strings.ReplaceAll(result, ": :", ":")
	}
	for strings.Contains(result, "  ") {
		result = strings.ReplaceAll(result, "  ", " ")
	}

	// Clean up trailing/leading separators
	result = strings.TrimSpace(result)
	result = strings.TrimSuffix(result, ":")
	result = strings.TrimSpace(result)

	// Final cleanup - trim colon again in case space trimming revealed one
	result = strings.TrimSuffix(result, ":")
	result = strings.TrimSpace(result)

	return result
}

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

// ErrFromParse creates a ParseError with a combined message and optional wrapped error.
//
// The message parameter should combine the operation prefix with the description.
// Always use predefined constants (PrefixParse, PrefixParseString, etc.) for consistency.
//
// Examples:
//
//	// With wrapped error
//	ErrFromParse(PrefixParse + `: invalid jws message: %w`, err)
//
//	// With format arguments
//	ErrFromParse(PrefixParse + `: failed at layer #%d: %w`, layerNum, err)
//
//	// Without wrapped error
//	ErrFromParse(PrefixParse + `: token is empty`)
//
// The %w verb is automatically removed from the message before formatting.
// If wrappedErr is nil, a simple error is returned instead of using errchain.
//
// The error chain is preserved intact. errchain's Concise mode will hide intermediate
// messages by default, but Verbose mode (%+v) will show the full chain.
func ErrFromParse(message string, args ...any) error {
	var wrappedErr error
	var formatArgs []any

	// Separate error from non-error arguments
	for _, arg := range args {
		if err, ok := arg.(error); ok {
			if wrappedErr == nil {
				wrappedErr = err
			}
			// Don't add errors to formatArgs
		} else {
			formatArgs = append(formatArgs, arg) // Only non-error args
		}
	}

	// No error to wrap - create simple error
	if wrappedErr == nil {
		// Remove %w from message since we're not wrapping anything
		cleanMessage := removePercentW(message)

		// Apply format arguments if any
		if len(formatArgs) > 0 && cleanMessage != "" {
			cleanMessage = fmt.Sprintf(cleanMessage, formatArgs...)
		}

		// Return simple error (not wrapped)
		return ParseError{stderrors.New(cleanMessage)}
	}

	// Past this point, wrappedErr is not nil
	message = removePercentW(message)

	// Apply format arguments if any
	if len(formatArgs) > 0 && message != "" {
		message = fmt.Sprintf(message, formatArgs...)
	}

	// Single wrap with combined message
	return ParseError{errchain.Wrap(stderrors.New(message), wrappedErr)}
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

// ErrFromValidate creates a ValidationError with a combined message and optional wrapped error.
//
// The message parameter should combine the operation prefix with the description.
// Always use predefined constants for consistency.
//
// Examples:
//
//	// With wrapped error
//	ErrFromValidate("jwt.Validate: validation failed: %w", expCheckErr)
//
//	// Without wrapped error
//	ErrFromValidate("jwt.Validate: invalid validator option")
//
// The %w verb is automatically removed from the message before formatting.
// If wrappedErr is nil, a simple error is returned instead of using errchain.
//
// The error chain is preserved intact. errchain's Concise mode will hide intermediate
// messages by default, but Verbose mode (%+v) will show the full chain.
func ErrFromValidate(message string, args ...any) error {
	var wrappedErr error
	var formatArgs []any

	// Separate error from non-error arguments
	for _, arg := range args {
		if err, ok := arg.(error); ok {
			if wrappedErr == nil {
				wrappedErr = err
			}
		} else {
			formatArgs = append(formatArgs, arg)
		}
	}

	if wrappedErr == nil {
		// Remove %w from message since we're not wrapping anything
		cleanMessage := removePercentW(message)

		// Apply format arguments if any
		if len(formatArgs) > 0 && cleanMessage != "" {
			cleanMessage = fmt.Sprintf(cleanMessage, formatArgs...)
		}

		// Return simple error (not wrapped)
		return ValidationError{stderrors.New(cleanMessage)}
	}

	// Past this point, wrappedErr is not nil

	// Remove %w verb from format string
	message = removePercentW(message)

	if len(formatArgs) > 0 && message != "" {
		message = fmt.Sprintf(message, formatArgs...)
	}

	return ValidationError{errchain.Wrap(stderrors.New(message), wrappedErr)}
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

// ErrFromIssuer creates an InvalidIssuerError with a combined message and optional wrapped error.
//
// The message parameter should include the complete error description.
//
// Examples:
//
//	// With format arguments
//	ErrFromIssuer(`"iss" not satisfied: token issuer mismatch (expected %q, got %q)`, expected, actual)
//
//	// With wrapped error
//	ErrFromIssuer(`"iss" not satisfied: %w`, err)
//
// The %w verb is automatically removed from the message before formatting.
// If wrappedErr is nil, a simple error is returned instead of using errchain.
//
// The error chain is preserved intact. errchain's Concise mode will hide intermediate
// messages by default, but Verbose mode (%+v) will show the full chain.
func ErrFromIssuer(message string, args ...any) error {
	var wrappedErr error
	var formatArgs []any

	for _, arg := range args {
		if err, ok := arg.(error); ok {
			if wrappedErr == nil {
				wrappedErr = err
			}
		} else {
			formatArgs = append(formatArgs, arg)
		}
	}

	if wrappedErr == nil {
		// Remove %w from message since we're not wrapping anything
		cleanMessage := removePercentW(message)

		// Apply format arguments if any
		if len(formatArgs) > 0 && cleanMessage != "" {
			cleanMessage = fmt.Sprintf(cleanMessage, formatArgs...)
		}

		// Return simple error (not wrapped)
		return InvalidIssuerError{stderrors.New(cleanMessage)}
	}

	// Past this point, wrappedErr is not nil

	message = removePercentW(message)
	if len(formatArgs) > 0 && message != "" {
		message = fmt.Sprintf(message, formatArgs...)
	}

	return InvalidIssuerError{errchain.Wrap(stderrors.New(message), wrappedErr)}
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

// ErrFromTokenExpired creates a TokenExpiredError with a combined message and optional wrapped error.
//
// The message parameter should include the complete error description.
//
// Examples:
//
//	// Simple expiration error
//	ErrFromTokenExpired(`"exp" not satisfied: token is expired`)
//
//	// With wrapped error
//	ErrFromTokenExpired(`"exp" not satisfied: %w`, err)
//
// The %w verb is automatically removed from the message before formatting.
// If wrappedErr is nil, a simple error is returned instead of using errchain.
//
// The error chain is preserved intact. errchain's Concise mode will hide intermediate
// messages by default, but Verbose mode (%+v) will show the full chain.
func ErrFromTokenExpired(message string, args ...any) error {
	var wrappedErr error
	var formatArgs []any

	for _, arg := range args {
		if err, ok := arg.(error); ok {
			if wrappedErr == nil {
				wrappedErr = err
			}
		} else {
			formatArgs = append(formatArgs, arg)
		}
	}

	if wrappedErr == nil {
		cleanMessage := removePercentW(message)
		if len(formatArgs) > 0 && cleanMessage != "" {
			cleanMessage = fmt.Sprintf(cleanMessage, formatArgs...)
		}
		return TokenExpiredError{stderrors.New(cleanMessage)}
	}

	message = removePercentW(message)
	if len(formatArgs) > 0 && message != "" {
		message = fmt.Sprintf(message, formatArgs...)
	}

	return TokenExpiredError{errchain.Wrap(stderrors.New(message), wrappedErr)}
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

// ErrFromInvalidIssuedAt creates an InvalidIssuedAtError with a combined message and optional wrapped error.
//
// The message parameter should include the complete error description.
//
// Examples:
//
//	// Simple issuedAt error
//	ErrFromInvalidIssuedAt(`"iat" not satisfied: token was issued in the future`)
//
//	// With wrapped error
//	ErrFromInvalidIssuedAt(`"iat" not satisfied: %w`, err)
//
// The %w verb is automatically removed from the message before formatting.
// If wrappedErr is nil, a simple error is returned instead of using errchain.
//
// The error chain is preserved intact. errchain's Concise mode will hide intermediate
// messages by default, but Verbose mode (%+v) will show the full chain.
func ErrFromInvalidIssuedAt(message string, args ...any) error {
	var wrappedErr error
	var formatArgs []any

	for _, arg := range args {
		if err, ok := arg.(error); ok {
			if wrappedErr == nil {
				wrappedErr = err
			}
		} else {
			formatArgs = append(formatArgs, arg)
		}
	}

	if wrappedErr == nil {
		cleanMessage := removePercentW(message)
		if len(formatArgs) > 0 && cleanMessage != "" {
			cleanMessage = fmt.Sprintf(cleanMessage, formatArgs...)
		}
		return InvalidIssuedAtError{stderrors.New(cleanMessage)}
	}

	message = removePercentW(message)
	if len(formatArgs) > 0 && message != "" {
		message = fmt.Sprintf(message, formatArgs...)
	}

	return InvalidIssuedAtError{errchain.Wrap(stderrors.New(message), wrappedErr)}
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

// ErrFromTokenNotYetValid creates a TokenNotYetValidError with a combined message and optional wrapped error.
//
// The message parameter should include the complete error description.
//
// Examples:
//
//	// Simple not-yet-valid error
//	ErrFromTokenNotYetValid(`"nbf" not satisfied: token not yet valid`)
//
//	// With wrapped error
//	ErrFromTokenNotYetValid(`"nbf" not satisfied: %w`, err)
//
// The %w verb is automatically removed from the message before formatting.
// If wrappedErr is nil, a simple error is returned instead of using errchain.
//
// The error chain is preserved intact. errchain's Concise mode will hide intermediate
// messages by default, but Verbose mode (%+v) will show the full chain.
func ErrFromTokenNotYetValid(message string, args ...any) error {
	var wrappedErr error
	var formatArgs []any

	for _, arg := range args {
		if err, ok := arg.(error); ok {
			if wrappedErr == nil {
				wrappedErr = err
			}
		} else {
			formatArgs = append(formatArgs, arg)
		}
	}

	if wrappedErr == nil {
		cleanMessage := removePercentW(message)
		if len(formatArgs) > 0 && cleanMessage != "" {
			cleanMessage = fmt.Sprintf(cleanMessage, formatArgs...)
		}
		return TokenNotYetValidError{stderrors.New(cleanMessage)}
	}

	message = removePercentW(message)
	if len(formatArgs) > 0 && message != "" {
		message = fmt.Sprintf(message, formatArgs...)
	}

	return TokenNotYetValidError{errchain.Wrap(stderrors.New(message), wrappedErr)}
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

// ErrFromAudience creates an InvalidAudienceError with a combined message and optional wrapped error.
//
// The message parameter should include the complete error description.
//
// Examples:
//
//	// With format arguments
//	ErrFromAudience(`"aud" not satisfied: token audience not found (expected %q)`, expected)
//
//	// With wrapped error
//	ErrFromAudience(`"aud" not satisfied: %w`, err)
//
// The %w verb is automatically removed from the message before formatting.
// If wrappedErr is nil, a simple error is returned instead of using errchain.
//
// The error chain is preserved intact. errchain's Concise mode will hide intermediate
// messages by default, but Verbose mode (%+v) will show the full chain.
func ErrFromAudience(message string, args ...any) error {
	var wrappedErr error
	var formatArgs []any

	for _, arg := range args {
		if err, ok := arg.(error); ok {
			if wrappedErr == nil {
				wrappedErr = err
			}
		} else {
			formatArgs = append(formatArgs, arg)
		}
	}

	if wrappedErr == nil {
		cleanMessage := removePercentW(message)
		if len(formatArgs) > 0 && cleanMessage != "" {
			cleanMessage = fmt.Sprintf(cleanMessage, formatArgs...)
		}
		return InvalidAudienceError{stderrors.New(cleanMessage)}
	}

	message = removePercentW(message)
	if len(formatArgs) > 0 && message != "" {
		message = fmt.Sprintf(message, formatArgs...)
	}

	return InvalidAudienceError{errchain.Wrap(stderrors.New(message), wrappedErr)}
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
