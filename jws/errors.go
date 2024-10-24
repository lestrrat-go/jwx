package jws

import (
	"fmt"
)

type errSign struct {
	error
}

var emptySignErr = errSign{fmt.Errorf(`jws.Sign: unknown error`)}

// SignError returns an error that can be passed to `errors.Is` to check if the error is a sign error.
func SignError() error {
	return emptySignErr
}

func (e errSign) Unwrap() error {
	return e.error
}

func (errSign) Is(err error) bool {
	_, ok := err.(errSign)
	return ok
}

func signerr(f string, args ...any) error {
	return errSign{fmt.Errorf(`jws.Sign: `+f, args...)}
}

// This error is returned when jws.Verify fails, but note that there's another type of
// message that can be returned by jws.Verify, which is `errVerification`.
type errVerify struct {
	error
}

var emptyVerifyErr = errVerify{fmt.Errorf(`jws.Verify: unknown error`)}

// VerifyError returns an error that can be passed to `errors.Is` to check if the error is a verify error.
func VerifyError() error {
	return emptyVerifyErr
}

func (e errVerify) Unwrap() error {
	return e.error
}

func (errVerify) Is(err error) bool {
	_, ok := err.(errVerify)
	return ok
}

func verifyerr(f string, args ...any) error {
	return errVerify{fmt.Errorf(`jws.Verify: `+f, args...)}
}

// errVerification is returned when the actual _verification_ of the key/payload fails.
type errVerification struct {
	error
}

var emptyVerificationErr = errVerification{fmt.Errorf(`jws.Verify: unknown error`)}

// VerificationError returns an error that can be passed to `errors.Is` to check if the error is a verification error.
func VerificationError() error {
	return emptyVerificationErr
}

func (e errVerification) Unwrap() error {
	return e.error
}

func (errVerification) Is(err error) bool {
	_, ok := err.(errVerification)
	return ok
}

type errParse struct {
	error
}

var emptyParseErr = errParse{fmt.Errorf(`jws.Parse: unknown error`)}

// ParseError returns an error that can be passed to `errors.Is` to check if the error is a parse error.
func ParseError() error {
	return emptyParseErr
}

func (e errParse) Unwrap() error {
	return e.error
}

func (errParse) Is(err error) bool {
	_, ok := err.(errParse)
	return ok
}

func bparseerr(prefix string, f string, args ...any) error {
	return errParse{fmt.Errorf(prefix+": "+f, args...)}
}

func parseerr(f string, args ...any) error {
	return bparseerr(`jws.Parse`, f, args...)
}

func sparseerr(f string, args ...any) error {
	return bparseerr(`jws.ParseString`, f, args...)
}

func rparseerr(f string, args ...any) error {
	return bparseerr(`jws.ParseReader`, f, args...)
}
