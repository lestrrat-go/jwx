package jwt

import (
	"errors"
	"fmt"
)

var errUnknownPayloadType = errors.New(`unknown payload type (payload is not JWT?)`)

// UnknownPayloadTypeError returns the opaque error value that is returned when
// `jwt.Parse` fails due to not being able to deduce the format of
// the incoming buffer
func UnknownPayloadTypeError() error {
	return errUnknownPayloadType
}

type parseError struct {
	error
}

var errDefaultParseError = parseerr(`jwt.Parse`, `unknown error`)

// ParseError returns an error that can be passed to `errors.Is` to check if the error is a parse error.
func ParseError() error {
	return errDefaultParseError
}

func (e parseError) Unwrap() error {
	return e.error
}

func (parseError) Is(err error) bool {
	_, ok := err.(parseError)
	return ok
}

func parseerr(prefix string, f string, args ...any) error {
	return parseError{fmt.Errorf(prefix+": "+f, args...)}
}

type validationError struct {
	error
}

var errDefaultValidateError = validateerr(`unknown error`)

func ValidateError() error {
	return errDefaultValidateError
}

func (validationError) Is(err error) bool {
	_, ok := err.(validationError)
	return ok
}

func (err validationError) Unwrap() error {
	return err.error
}

func validateerr(f string, args ...any) error {
	return validationError{fmt.Errorf(`jwt.Validate: `+f, args...)}
}

type invalidIssuerError struct {
	error
}

func (err invalidIssuerError) Is(target error) bool {
	_, ok := target.(invalidIssuerError)
	return ok
}

func (err invalidIssuerError) Unwrap() error {
	return err.error
}

func issuererr(f string, args ...any) error {
	return invalidIssuerError{fmt.Errorf(`"iss" not satisfied: `+f, args...)}
}

var errDefaultInvalidIssuer = invalidIssuerError{errors.New(`"iss" not satisfied`)}

// InvalidIssuerError returns the immutable error used when `iss` claim
// is not satisfied
//
// The return value should only be used for comparison using `errors.Is()`
func InvalidIssuerError() error {
	return errDefaultInvalidIssuer
}

type tokenExpiredError struct {
	error
}

func (err tokenExpiredError) Is(target error) bool {
	_, ok := target.(tokenExpiredError)
	return ok
}

func (err tokenExpiredError) Unwrap() error {
	return err.error
}

var errDefaultTokenExpired = tokenExpiredError{errors.New(`"exp" not satisfied: token is expired`)}

// TokenExpiredError returns the immutable error used when `exp` claim
// is not satisfied.
//
// The return value should only be used for comparison using `errors.Is()`
func TokenExpiredError() error {
	return errDefaultTokenExpired
}

type invalidIssuedAtError struct {
	error
}

func (err invalidIssuedAtError) Is(target error) bool {
	_, ok := target.(invalidIssuedAtError)
	return ok
}

func (err invalidIssuedAtError) Unwrap() error {
	return err.error
}

var errDefaultInvalidIssuedAt = invalidIssuedAtError{errors.New(`"iat" not satisfied`)}

// InvalidIssuedAtError returns the immutable error used when `iat` claim
// is not satisfied
//
// The return value should only be used for comparison using `errors.Is()`
func InvalidIssuedAtError() error {
	return errDefaultInvalidIssuedAt
}

type tokenNotYetValidError struct {
	error
}

func (err tokenNotYetValidError) Is(target error) bool {
	_, ok := target.(tokenNotYetValidError)
	return ok
}

func (err tokenNotYetValidError) Unwrap() error {
	return err.error
}

var errDefaultTokenNotYetValid = tokenNotYetValidError{errors.New(`"nbf" not satisfied: token is not yet valid`)}

// TokenNotYetValidError returns the immutable error used when `nbf` claim
// is not satisfied
//
// The return value should only be used for comparison using `errors.Is()`
func TokenNotYetValidError() error {
	return errDefaultTokenNotYetValid
}

type invalidAudienceError struct {
	error
}

func (err invalidAudienceError) Is(target error) bool {
	_, ok := target.(invalidAudienceError)
	return ok
}

func (err invalidAudienceError) Unwrap() error {
	return err.error
}

func auderr(f string, args ...any) error {
	return invalidAudienceError{fmt.Errorf(`"aud" not satisfied: `+f, args...)}
}

var errDefaultInvalidAudience = invalidAudienceError{errors.New(`"aud" not satisfied`)}

// InvalidAudienceError returns the immutable error used when `aud` claim
// is not satisfied
//
// The return value should only be used for comparison using `errors.Is()`
func InvalidAudienceError() error {
	return errDefaultInvalidAudience
}

type missingRequiredClaimError struct {
	error
	claim string
}

func (err *missingRequiredClaimError) Is(target error) bool {
	err1, ok := target.(*missingRequiredClaimError)
	if !ok {
		return false
	}
	return err1 == errDefaultMissingRequiredClaim || err1.claim == err.claim
}

var errDefaultMissingRequiredClaim = &missingRequiredClaimError{error: errors.New(`required claim is missing`)}

func errMissingRequiredClaim(name string) error {
	return &missingRequiredClaimError{claim: name, error: fmt.Errorf(`required claim "%s" is missing`, name)}
}

// MissingRequiredClaimError returns the immutable error used when the claim
// specified by `jwt.IsRequired()` is not present.
//
// The return value should only be used for comparison using `errors.Is()`
func MissingRequiredClaimError() error {
	return errDefaultMissingRequiredClaim
}
