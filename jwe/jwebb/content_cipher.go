package jwebb

import (
	"fmt"
	"sync"

	"github.com/lestrrat-go/jwx/v4/internal/tokens"
	"github.com/lestrrat-go/jwx/v4/jwe/internal/cipher"
	"github.com/lestrrat-go/jwx/v4/jwe/internal/content_crypt"
)

var contentCipherCache sync.Map // map[string]content_crypt.Cipher

// ContentEncryptionIsSupported checks if the content encryption algorithm is supported
func ContentEncryptionIsSupported(alg string) bool {
	switch alg {
	case tokens.A128GCM, tokens.A192GCM, tokens.A256GCM,
		tokens.A128CBC_HS256, tokens.A192CBC_HS384, tokens.A256CBC_HS512:
		return true
	default:
		return false
	}
}

// CreateContentCipher creates a content encryption cipher for the given algorithm string
func CreateContentCipher(alg string) (content_crypt.Cipher, error) {
	if v, ok := contentCipherCache.Load(alg); ok {
		//nolint:forcetypeassert
		return v.(content_crypt.Cipher), nil
	}

	if !ContentEncryptionIsSupported(alg) {
		return nil, fmt.Errorf(`invalid content cipher algorithm (%s)`, alg)
	}

	c, err := cipher.NewAES(alg)
	if err != nil {
		return nil, fmt.Errorf(`failed to build content cipher for %s: %w`, alg, err)
	}

	contentCipherCache.Store(alg, c)
	return c, nil
}
