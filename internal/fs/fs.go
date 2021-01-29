// +build go1.16

package fs

import (
	"bytes"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/lestrrat-go/option"
	"github.com/pkg/errors"
)

type FS = fs.FS

type identFS struct{}

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

type inMemoryEntry struct {
	name  string
	size  int64
	mode  fs.FileMode
	mtime time.Time
	rdr   *bytes.Reader
}

func (e *inMemoryEntry) Stat() (fs.FileInfo, error) {
	return e, nil
}

func (e *inMemoryEntry) Read(buf []byte) (int, error) { return e.rdr.Read(buf) }
func (e *inMemoryEntry) Close() error                 { return nil }
func (e *inMemoryEntry) Name() string                 { return e.name }
func (e *inMemoryEntry) Size() int64                  { return e.size }
func (e *inMemoryEntry) Mode() fs.FileMode            { return e.mode }
func (e *inMemoryEntry) ModTime() time.Time           { return e.mtime }
func (e *inMemoryEntry) IsDir() bool                  { return false }
func (e *inMemoryEntry) Sys() interface{}             { return nil }

type InMemory struct {
	data map[string]*inMemoryEntry
}

func NewInMemory(dir string) (*InMemory, error) {
	fs := &InMemory{
		data: make(map[string]*inMemoryEntry),
	}

	filepath.Walk(dir, filepath.WalkFunc(func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		buf, err := ioutil.ReadFile(path)
		if err != nil {
			return errors.Wrapf(err, `failed to read %s`, path)
		}
		fs.data[path] = &inMemoryEntry{
			name:  info.Name(),
			size:  info.Size(),
			mode:  info.Mode(),
			mtime: info.ModTime(),
			rdr:   bytes.NewReader(buf),
		}
		return nil
	}))

	return fs, nil
}

func (fs *InMemory) Open(path string) (fs.File, error) {
	data, ok := fs.data[path]
	if !ok {
		return nil, errors.Errorf(`file not found %s`, path)
	}

	return data, nil
}
