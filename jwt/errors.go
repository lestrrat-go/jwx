package jwt

import (
	"fmt"
)

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
