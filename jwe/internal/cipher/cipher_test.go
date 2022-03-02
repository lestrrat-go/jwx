package cipher_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe/internal/cipher"
	"github.com/stretchr/testify/assert"
)

func TestAES(t *testing.T) {
	algs := []jwa.ContentEncryptionAlgorithm{
		jwa.A128GCM,
		jwa.A192GCM,
		jwa.A256GCM,
		jwa.A128CBC_HS256,
		jwa.A192CBC_HS384,
		jwa.A256CBC_HS512,
	}
	for _, alg := range algs {
		c, err := cipher.NewAES(alg)
		if !assert.NoError(t, err, "BuildCipher for %s succeeds", alg) {
			return
		}
		t.Logf("keysize = %d", c.KeySize())
	}
}
