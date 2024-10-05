package cipher_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe/internal/cipher"
	"github.com/stretchr/testify/require"
)

func TestAES(t *testing.T) {
	algs := []jwa.ContentEncryptionAlgorithm{
		jwa.A128GCM(),
		jwa.A192GCM(),
		jwa.A256GCM(),
		jwa.A128CBC_HS256(),
		jwa.A192CBC_HS384(),
		jwa.A256CBC_HS512(),
	}
	for _, alg := range algs {
		c, err := cipher.NewAES(alg)
		require.NoError(t, err, "BuildCipher for %s succeeds", alg)
		t.Logf("keysize = %d", c.KeySize())
	}
}
