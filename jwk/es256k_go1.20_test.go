//go:build jwx_es256k && jwx_secp256k1_pem && go1.20

package jwk_test

import (
	"fmt"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"
)

func TestES256KPem(t *testing.T) {
	raw, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err, `GeneratePrivateKey should succeed`)

	testcases := []interface{}{raw.ToECDSA(), raw.PubKey().ToECDSA()}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("Marshal %T", tc), func(t *testing.T) {
			key, err := jwk.FromRaw(tc)
			require.NoError(t, err, `FromRaw should succeed`)

			pem, err := jwk.Pem(key)
			require.NoError(t, err, `Pem should succeed`)
			require.NotEmpty(t, pem, `Pem should not be empty`)

			parsed, err := jwk.Parse(pem, jwk.WithPEM(true))
			require.NoError(t, err, `Parse should succeed`)
			_ = parsed
		})
	}

	t.Run("ParsePKCS8PrivateKey", func(t *testing.T) {
		const src = `-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQggS9t6iYyj9JSL+btkMEq
pMYitWV4X+/Jg9zu3L8Ob5ShRANCAAT/YrxWHfw3e8lfDncJLLkPRbdby0L4qT95
vyWU5lPpSwRbEAfSFR1E5RD9irkN1mCY8D1ko1PAlmHVB78pNzq4
-----END PRIVATE KEY-----`
		key, err := jwk.Parse([]byte(src), jwk.WithPEM(true))
		require.NoError(t, err, `Parse should succeed`)
		require.NotNil(t, key, `key should not be nil`)
	})
}
