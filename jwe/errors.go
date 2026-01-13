package jwe

import (
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/internal/errchain"
)

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

func errFromEncrypt(f string, args ...any) error {
	innerErr := fmt.Errorf(f, args...)
	return encryptError{errchain.Wrap(errors.New("jwe.Encrypt"), innerErr)}
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

func errFromDecrypt(f string, args ...any) error {
	innerErr := fmt.Errorf(f, args...)
	return decryptError{errchain.Wrap(errors.New("jwe.Decrypt"), innerErr)}
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

func errFromRecipient(f string, args ...any) error {
	innerErr := fmt.Errorf(f, args...)
	return recipientError{errchain.Wrap(errors.New("jwe recipient"), innerErr)}
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

func bparseerr(prefix string, f string, args ...any) error {
	innerErr := fmt.Errorf(f, args...)
	return parseError{errchain.Wrap(errors.New(prefix), innerErr)}
}

// Error prefixes for errFromParse calls
const (
	prefixParse       = "jwe.Parse"
	prefixParseReader = "jwe.ParseReader"
	prefixParseString = "jwe.ParseString"
)

func errFromParse(prefix, f string, args ...any) error {
	return bparseerr(prefix, f, args...)
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
func errFromField(f string, args ...any) error {
	innerErr := fmt.Errorf(f, args...)
	return errchain.Wrap(errors.New("jwe.Headers"), innerErr)
}
