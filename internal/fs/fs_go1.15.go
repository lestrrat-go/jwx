// +build !go1.16

package fs

import (
	"os"

	"github.com/pkg/errors"
)

func Open(path string, options ...OpenOption) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.Wrapf(err, `failed to open %s`, path)
	}
	return f, nil
}
