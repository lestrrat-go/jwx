package jws

import (
	"errors"
	"fmt"
)

// errCritPresent is returned by VerifyCompactFast when the protected
// header carries a "crit" list. The fast path cannot enforce RFC 7515
// §4.1.11 (it has no WithCritExtension allowlist), so it refuses rather
// than silently accepting. Callers that wrap VerifyCompactFast and want
// the full validateCritical rule set applied should detect this via
// errors.Is(err, jws.ErrCritPresent()) and retry through jws.Verify.
var errCritPresent = errors.New("VerifyCompactFast: protected header contains \"crit\"; use jws.Verify")

// ErrCritPresent returns the sentinel error returned by VerifyCompactFast
// when the protected header contains a "crit" list. Callers that front
// VerifyCompactFast with an auto-fallback to jws.Verify can detect it
// via errors.Is.
func ErrCritPresent() error {
	return errCritPresent
}

type signError struct {
	error
}

const (
	prefixJwsSign    = `jws.Sign`
	prefixJwsCompact = `jws.Compact`
)

var errDefaultSignError = makeSignError(prefixJwsSign, `unknown error`)

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

func makeSignError(prefix string, f string, args ...any) error {
	return signError{fmt.Errorf(prefix+`: `+f, args...)}
}

// This error is returned when jws.Verify fails, but note that there's another type of
// message that can be returned by jws.Verify, which is `errVerification`.
type verifyError struct {
	error
}

var errDefaultVerifyError = makeVerifyError(`unknown error`)

// VerifyError returns an error that can be passed to `errors.Is` to check if the error is a verify error.
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

func makeVerifyError(f string, args ...any) error {
	return verifyError{fmt.Errorf(`jws.Verify: `+f, args...)}
}

// verificationError is returned when the actual _verification_ of the key/payload fails.
type verificationError struct {
	error
}

var errDefaultVerificationError = verificationError{fmt.Errorf(`unknown verification error`)}

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

type parseError struct {
	error
}

var errDefaultParseError = makeParseError(`jws.Parse`, `unknown error`)

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

func makeParseError(prefix string, f string, args ...any) error {
	return parseError{fmt.Errorf(prefix+": "+f, args...)}
}
