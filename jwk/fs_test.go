// +build go1.16

package jwk_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/internal/fs"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"
)

func TestFS(t *testing.T) {
	testdata, err := fs.NewInMemory("testdata")
	if !assert.NoError(t, err, `fs.NewInMemory should succeed`) {
		return
	}

	key, err := jwk.ReadFile("testdata/rs256.jwk", jwk.WithFS(testdata))
	if !assert.NoError(t, err, `jwk.ReadFile + WithFS should succeed`) {
		return
	}
	_ = key
}
