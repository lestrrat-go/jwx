package jwxio

import (
	"bytes"
	"errors"
	"io"
	"strings"
)

var errNonFiniteSource = errors.New(`cannot read from non-finite source`)
var errInputTooLarge = errors.New(`input exceeds maximum size`)

func NonFiniteSourceError() error {
	return errNonFiniteSource
}

func InputTooLargeError() error {
	return errInputTooLarge
}

// ReadAllFromFiniteSource reads all data from a io.Reader if it comes from a
// finite source whose remaining size does not exceed maxBytes.
func ReadAllFromFiniteSource(rdr io.Reader, maxBytes int64) ([]byte, error) {
	var remaining int64
	switch rdr := rdr.(type) {
	case *bytes.Reader:
		remaining = int64(rdr.Len())
	case *bytes.Buffer:
		remaining = int64(rdr.Len())
	case *io.LimitedReader:
		remaining = rdr.N
	case *strings.Reader:
		remaining = int64(rdr.Len())
	default:
		return nil, errNonFiniteSource
	}

	if remaining > maxBytes {
		return nil, errInputTooLarge
	}

	data, err := io.ReadAll(rdr)
	if err != nil {
		return nil, err
	}
	return data, nil
}
