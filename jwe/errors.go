package jwe

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

type encryptError struct {
	error
}

func (e encryptError) Unwrap() error {
	return e.error
}

func (encryptError) Is(err error) bool {
	_, ok := err.(encryptError)
	return ok
}

func errFromEncrypt(message string, args ...any) error {
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

	fullMessage := "jwe.Encrypt"
	if message != "" {
		fullMessage = fullMessage + ": " + message
	}

	if wrappedErr == nil {
		return encryptError{errors.New(fullMessage)}
	}

	return encryptError{errchain.Wrap(errors.New(fullMessage), wrappedErr)}
}

var errDefaultEncryptError = encryptError{errors.New(`encrypt error`)}

// EncryptError returns an error that can be passed to `errors.Is` to check if the error is an error returned by `jwe.Encrypt`.
func EncryptError() error {
	return errDefaultEncryptError
}

type decryptError struct {
	error
}

func (e decryptError) Unwrap() error {
	return e.error
}

func (decryptError) Is(err error) bool {
	_, ok := err.(decryptError)
	return ok
}

func errFromDecrypt(message string, args ...any) error {
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

	fullMessage := "jwe.Decrypt"
	if message != "" {
		fullMessage = fullMessage + ": " + message
	}

	if wrappedErr == nil {
		return decryptError{errors.New(fullMessage)}
	}

	return decryptError{errchain.Wrap(errors.New(fullMessage), wrappedErr)}
}

var errDefaultDecryptError = decryptError{errors.New(`decrypt error`)}

// DecryptError returns an error that can be passed to `errors.Is` to check if the error is an error returned by `jwe.Decrypt`.
//
// Errors from this package support standard error unwrapping via errors.Unwrap().
// Use fmt.Printf("%+v", err) to display the full error chain for debugging,
// or %s/%v for a concise user-friendly message.
func DecryptError() error {
	return errDefaultDecryptError
}

type recipientError struct {
	error
}

func (e recipientError) Unwrap() error {
	return e.error
}

func (recipientError) Is(err error) bool {
	_, ok := err.(recipientError)
	return ok
}

func errFromRecipient(message string, args ...any) error {
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

	fullMessage := "jwe recipient"
	if message != "" {
		fullMessage = fullMessage + ": " + message
	}

	if wrappedErr == nil {
		return recipientError{errors.New(fullMessage)}
	}

	return recipientError{errchain.Wrap(errors.New(fullMessage), wrappedErr)}
}

var errDefaultRecipientError = recipientError{errors.New(`recipient error`)}

// RecipientError returns an error that can be passed to `errors.Is` to check if the error is
// an error that occurred while attempting to decrypt a JWE message for a particular recipient.
//
// For example, if the JWE message failed to parse during `jwe.Decrypt`, it will be a
// `jwe.DecryptError`, but NOT `jwe.RecipientError`. However, if the JWE message could not
// be decrypted for any of the recipients, then it will be a `jwe.RecipientError`
// (actually, it will be _multiple_ `jwe.RecipientError` errors, one for each recipient)
func RecipientError() error {
	return errDefaultRecipientError
}

type parseError struct {
	error
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
	prefixParse       = "jwe.Parse"
	prefixParseReader = "jwe.ParseReader"
	prefixParseString = "jwe.ParseString"
)

func errFromParse(prefix, message string, args ...any) error {
	return bparseerr(prefix, message, args...)
}

var errDefaultParseError = parseError{errors.New(`parse error`)}

// ParseError returns an error that can be passed to `errors.Is` to check if the error
// is an error returned by `jwe.Parse` and related functions.
//
// Errors from this package support standard error unwrapping via errors.Unwrap().
// Use fmt.Printf("%+v", err) to display the full error chain for debugging,
// or %s/%v for a concise user-friendly message.
func ParseError() error {
	return errDefaultParseError
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
