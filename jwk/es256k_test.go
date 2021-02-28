// +build jwx_es256k

package jwk_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/internal/ecutil"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/stretchr/testify/assert"
)

func TestES256K(t *testing.T) {
	if !assert.True(t, ecutil.IsAvailable(jwa.Secp256k1), `jwa.Secp256k1 should be available`) {
		return
	}
}
