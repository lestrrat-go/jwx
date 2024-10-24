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
