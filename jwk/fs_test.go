// +build go1.16

package jwk_test

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestFS(t *testing.T) {
	var testdata = fstest.MapFS{}
	if err := filepath.Walk("testdata", filepath.WalkFunc(func(path string, info os.FileInfo, err error) error {
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
		testdata[path] = &fstest.MapFile{
			Mode:    info.Mode(),
			ModTime: info.ModTime(),
			Data:    buf,
		}
		return nil
	})); !assert.NoError(t, err, `filepath.Walk should succeed`) {
		return
	}

	key, err := jwk.ReadFile("testdata/rs256.jwk", jwk.WithFS(testdata))
	if !assert.NoError(t, err, `jwk.ReadFile + WithFS should succeed`) {
		return
	}
	_ = key
}
