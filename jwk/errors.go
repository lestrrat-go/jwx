package jwk

import (
	"errors"
	"fmt"
	"reflect"
)

var cpe = &continueError{}

// ContinueError returns an opaque error that can be returned
// when a `KeyParser`, `KeyImporter`, or `KeyExporter` cannot handle the given payload,
// but would like the process to continue with the next handler.
func ContinueError() error {
	return cpe
}

type continueError struct{}

func (e *continueError) Error() string {
	return "continue parsing"
}

type importError struct {
	error
}

func (e importError) Unwrap() error {
	return e.error
}

func (importError) Is(err error) bool {
	_, ok := err.(importError)
	return ok
}

func importerr(f string, args ...any) error {
	return importError{fmt.Errorf(`jwk.Import: `+f, args...)}
}

var errDefaultImportError = importError{errors.New(`import error`)}

func ImportError() error {
	return errDefaultImportError
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
	return parseError{fmt.Errorf(prefix+`: `+f, args...)}
}

func parseerr(f string, args ...any) error {
	return bparseerr(`jwk.Parse`, f, args...)
}

func rparseerr(f string, args ...any) error {
	return bparseerr(`jwk.ParseReader`, f, args...)
}

func sparseerr(f string, args ...any) error {
	return bparseerr(`jwk.ParseString`, f, args...)
}

var errDefaultParseError = parseError{errors.New(`parse error`)}

func ParseError() error {
	return errDefaultParseError
}

//-------------------------------------------------------------------
// KeyTypeMismatchError
//-------------------------------------------------------------------

// KeyTypeMismatchError is returned by [Import] when the imported key's
// concrete type does not match the generic type parameter supplied by
// the caller.
//
// Callers that need to distinguish "wrong generic type parameter" from
// "key validation failed" should use [errors.Is] with
// KeyTypeMismatchError{}, or [errors.AsType] to recover the Got and
// Want fields.
type KeyTypeMismatchError struct {
	// Got is the runtime type of the key that was imported.
	Got reflect.Type
	// Want is the type requested via the Import type parameter.
	Want reflect.Type
}

func (e KeyTypeMismatchError) Error() string {
	return fmt.Sprintf(`imported key is %s, not %s`, typeName(e.Got), typeName(e.Want))
}

func (e KeyTypeMismatchError) Is(target error) bool {
	_, ok := target.(KeyTypeMismatchError)
	return ok
}

// typeName renders a reflect.Type similarly to the %T verb so that
// KeyTypeMismatchError's message remains recognizable when either
// field is nil.
func typeName(t reflect.Type) string {
	if t == nil {
		return "<nil>"
	}
	return t.String()
}

//-------------------------------------------------------------------
// FieldNotFoundError
//-------------------------------------------------------------------

// FieldNotFoundError is returned when jwk.Get fails to find the
// requested field on a jwk.Key.
type FieldNotFoundError struct {
	// Name is the name of the field that was not found.
	Name string
}

func (e FieldNotFoundError) Error() string {
	return fmt.Sprintf(`field %q not found`, e.Name)
}

func (e FieldNotFoundError) Is(target error) bool {
	_, ok := target.(FieldNotFoundError)
	return ok
}

//-------------------------------------------------------------------
// FieldTypeMismatchError
//-------------------------------------------------------------------

// FieldTypeMismatchError is returned when jwk.Get finds the
// requested field but the stored value cannot be converted to the
// requested type.
//
// Callers that need to distinguish "field missing" from "field present
// but wrong type" should use errors.Is with FieldNotFoundError{} /
// FieldTypeMismatchError{}, or errors.AsType to recover Name, Got,
// and Want fields.
type FieldTypeMismatchError struct {
	// Name is the name of the field whose value could not be converted.
	Name string
	// Got is the value currently stored under the field. Use %T to
	// inspect its concrete type.
	Got any
	// Want is a zero value of the requested type T. Use %T to inspect
	// its concrete type.
	Want any
}

func (e FieldTypeMismatchError) Error() string {
	return fmt.Sprintf(`field %q is %T, not %T`, e.Name, e.Got, e.Want)
}

func (e FieldTypeMismatchError) Is(target error) bool {
	_, ok := target.(FieldTypeMismatchError)
	return ok
}
