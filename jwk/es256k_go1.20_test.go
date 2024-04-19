//go:build jwx_es256k && go1.20

package jwk_test

import (
	"fmt"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1"
	"github.com/lestrrat-go/jwx/v2/jwk"
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
}
