package cipher_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/tokens"
	"github.com/lestrrat-go/jwx/v4/jwe/internal/cipher"
	"github.com/stretchr/testify/require"
)

func TestAES(t *testing.T) {
	algs := []string{
		tokens.A128GCM,
		tokens.A192GCM,
		tokens.A256GCM,
		tokens.A128CBC_HS256,
		tokens.A192CBC_HS384,
		tokens.A256CBC_HS512,
	}
	for _, alg := range algs {
		c, err := cipher.NewAES(alg)
		require.NoError(t, err, "BuildCipher for %s succeeds", alg)
		t.Logf("keysize = %d", c.KeySize())
	}
}
