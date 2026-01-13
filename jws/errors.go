package jws

import (
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/internal/errchain"
)

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

func errFromSign(f string, args ...any) error {
	innerErr := fmt.Errorf(f, args...)
	return signError{errchain.Wrap(errors.New("jws.Sign"), innerErr)}
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

func errFromVerify(f string, args ...any) error {
	innerErr := fmt.Errorf(f, args...)
	return verifyError{errchain.Wrap(errors.New("jws.Verify"), innerErr)}
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

func errFromVerification(f string, args ...any) error {
	innerErr := fmt.Errorf(f, args...)
	return verificationError{errchain.Wrap(errors.New("signature verification"), innerErr)}
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

func bparseerr(prefix string, f string, args ...any) error {
	innerErr := fmt.Errorf(f, args...)
	return parseError{errchain.Wrap(errors.New(prefix), innerErr)}
}

// Error prefixes for errFromParse calls
const (
	prefixParse       = "jws.Parse"
	prefixParseReader = "jws.ParseReader"
	prefixParseString = "jws.ParseString"
)

func errFromParse(prefix, f string, args ...any) error {
	return bparseerr(prefix, f, args...)
}

// errFromField wraps header field access errors (used by Headers.Get/Set methods)
func errFromField(f string, args ...any) error {
	innerErr := fmt.Errorf(f, args...)
	return errchain.Wrap(errors.New("jws.Headers"), innerErr)
}
