package jwk

import (
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/internal/errchain"
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

func errFromImport(f string, args ...any) error {
	innerErr := fmt.Errorf(f, args...)
	return importError{errchain.Wrap(errors.New("jwk.Import"), innerErr)}
}

var errDefaultImportError = importError{errors.New(`import error`)}

func ImportError() error {
	return errDefaultImportError
}

type exportError struct {
	error
}

func (e exportError) Unwrap() error {
	return e.error
}

func (exportError) Is(err error) bool {
	_, ok := err.(exportError)
	return ok
}

func errFromExport(f string, args ...any) error {
	innerErr := fmt.Errorf(f, args...)
	return exportError{errchain.Wrap(errors.New("jwk.Export"), innerErr)}
}

var errDefaultExportError = exportError{errors.New(`export error`)}

func ExportError() error {
	return errDefaultExportError
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
	prefixParse       = "jwk.Parse"
	prefixParseReader = "jwk.ParseReader"
	prefixParseString = "jwk.ParseString"
)

func errFromParse(prefix, f string, args ...any) error {
	return bparseerr(prefix, f, args...)
}

var errDefaultParseError = parseError{errors.New(`parse error`)}

func ParseError() error {
	return errDefaultParseError
}
