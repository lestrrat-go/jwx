package jws

import (
	"errors"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v3/internal/errchain"
)

// removePercentW removes %w and cleans up separators from format strings to prevent double-wrapping.
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

type signError struct {
	error
}

var errDefaultSignError = errFromSign(`unknown error`)

// SignError returns an error that can be passed to `errors.Is` to check if the error is a sign error.
func SignError() error {
	return errDefaultSignError
}

func (e signError) Unwrap() error {
	return e.error
}

func (signError) Is(err error) bool {
	_, ok := err.(signError)
	return ok
}

func errFromSign(message string, args ...any) error {
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

	message = removePercentW(message)
	if len(formatArgs) > 0 && message != "" {
		message = fmt.Sprintf(message, formatArgs...)
	}

	fullMessage := "jws.Sign"
	if message != "" {
		fullMessage = fullMessage + ": " + message
	}

	if wrappedErr == nil {
		return signError{errors.New(fullMessage)}
	}

	return signError{errchain.Wrap(errors.New(fullMessage), wrappedErr)}
}

// This error is returned when jws.Verify fails, but note that there's another type of
// message that can be returned by jws.Verify, which is `errVerification`.
type verifyError struct {
	error
}

var errDefaultVerifyError = errFromVerify(`unknown error`)

// VerifyError returns an error that can be passed to `errors.Is` to check if the error is a verify error.
//
// Errors from this package support standard error unwrapping via errors.Unwrap().
// Use fmt.Printf("%+v", err) to display the full error chain for debugging,
// or %s/%v for a concise user-friendly message.
func VerifyError() error {
	return errDefaultVerifyError
}

func (e verifyError) Unwrap() error {
	return e.error
}

func (verifyError) Is(err error) bool {
	_, ok := err.(verifyError)
	return ok
}

func errFromVerify(message string, args ...any) error {
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

	message = removePercentW(message)
	if len(formatArgs) > 0 && message != "" {
		message = fmt.Sprintf(message, formatArgs...)
	}

	fullMessage := "jws.Verify"
	if message != "" {
		fullMessage = fullMessage + ": " + message
	}

	if wrappedErr == nil {
		return verifyError{errors.New(fullMessage)}
	}

	return verifyError{errchain.Wrap(errors.New(fullMessage), wrappedErr)}
}

// verificationError is returned when the actual _verification_ of the key/payload fails.
type verificationError struct {
	error
}

var errDefaultVerificationError = errFromVerification(`unknown verification error`)

// VerificationError returns an error that can be passed to `errors.Is` to check if the error is a verification error.
func VerificationError() error {
	return errDefaultVerificationError
}

func (e verificationError) Unwrap() error {
	return e.error
}

func (verificationError) Is(err error) bool {
	_, ok := err.(verificationError)
	return ok
}

func errFromVerification(message string, args ...any) error {
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

	message = removePercentW(message)
	if len(formatArgs) > 0 && message != "" {
		message = fmt.Sprintf(message, formatArgs...)
	}

	fullMessage := "signature verification"
	if message != "" {
		fullMessage = fullMessage + ": " + message
	}

	if wrappedErr == nil {
		return verificationError{errors.New(fullMessage)}
	}

	return verificationError{errchain.Wrap(errors.New(fullMessage), wrappedErr)}
}

type parseError struct {
	error
}

var errDefaultParseError = errFromParse(prefixParse, `unknown error`)

// ParseError returns an error that can be passed to `errors.Is` to check if the error is a parse error.
//
// Errors from this package support standard error unwrapping via errors.Unwrap().
// Use fmt.Printf("%+v", err) to display the full error chain for debugging,
// or %s/%v for a concise user-friendly message.
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

func bparseerr(prefix string, message string, args ...any) error {
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

	fullMessage := prefix
	if message != "" {
		message = removePercentW(message)
		if len(formatArgs) > 0 {
			message = fmt.Sprintf(message, formatArgs...)
		}
		fullMessage = prefix + ": " + message
	}

	if wrappedErr == nil {
		return parseError{errors.New(fullMessage)}
	}

	return parseError{errchain.Wrap(errors.New(fullMessage), wrappedErr)}
}

// Error prefixes for errFromParse calls
const (
	prefixParse       = "jws.Parse"
	prefixParseReader = "jws.ParseReader"
	prefixParseString = "jws.ParseString"
)

func errFromParse(prefix, message string, args ...any) error {
	return bparseerr(prefix, message, args...)
}

// errFromField wraps header field access errors (used by Headers.Get/Set methods)
func errFromField(message string, args ...any) error {
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
		return errors.New(cleanMessage)
	}

	message = removePercentW(message)
	if len(formatArgs) > 0 && message != "" {
		message = fmt.Sprintf(message, formatArgs...)
	}

	return errchain.Wrap(errors.New(message), wrappedErr)
}
