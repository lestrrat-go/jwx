// +build go1.16

package fs

import (
	"io/fs"
	"os"

	"github.com/lestrrat-go/option"
	"github.com/pkg/errors"
)

type FS = fs.FS
type Option = option.Interface

type identFS struct{}

type OpenOption interface {
	Option
	openOption()
}

type openOption struct {
	Option
}

// Wrap another option and make it an OpenOption
func NewOpenOption(o Option) OpenOption {
	return &openOption{o}
}

func (o *openOption) openOption() {}

func WithFS(v fs.FS) OpenOption {
	return &openOption{option.New(identFS{}, v)}
}

type Local struct{}

func (Local) Open(path string) (fs.File, error) {
	return os.Open(path)
}

func Open(path string, options ...OpenOption) (fs.File, error) {
	var xfs fs.FS = Local{}
	for _, option := range options {
		switch option.Ident() {
		case identFS{}:
			xfs = option.Value().(fs.FS)
		}
	}

	f, err := xfs.Open(path)
	if err != nil {
		return nil, errors.Wrapf(err, `failed to open %s`, path)
	}
	return f, nil
}
