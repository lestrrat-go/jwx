// +build go1.16

package jwk_test

import (
	"embed"
	"testing"
	
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"
)

//go:embed testdata
var testdata embed.FS

func TestFS(t *testing.T) {
	key, err := jwk.ReadFile("testdata/rs256.jwk", jwk.WithFS(testdata))
	if !assert.NoError(t, err, `jwk.ReadFile + WithFS should succeed`) {
		return
	}
	_ = key
}
