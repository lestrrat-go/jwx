//go:build jwx_es256k
// +build jwx_es256k

package jwk_test

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lestrrat-go/jwx/v2/internal/ecutil"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/require"
)

func TestES256K(t *testing.T) {
	require.True(t, ecutil.IsAvailable(jwa.Secp256k1), `jwa.Secp256k1 should be available`)
}

func BenchmarkKeyInstantiation(b *testing.B) {
	const xb64 = "YAXIamcY9mIhcTp3BzxBKRzDq7_NA6pJVemytQ2_f5s"
	const yb64 = "ZnLa0NRq3mHjgveYiKc-p4mdlBm-zx1snsIIfBGI-hg"

	x, err := base64.RawURLEncoding.DecodeString(xb64)
	require.NoError(b, err, `DecodeBase64 should succeed`)
	y, err := base64.RawURLEncoding.DecodeString(yb64)
	require.NoError(b, err, `DecodeBase64 should succeed`)

	b.Run("Use json.Marshal/json.Unmarshal", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			serialized, err := json.Marshal(map[string]interface{}{
				"kty": "EC",
				"crv": "secp256k1",
				"x":   xb64,
				"y":   yb64,
			})
			if err != nil {
				panic(err)
			}

			key, err := jwk.Parse(serialized)
			if err != nil {
				panic(err)
			}
			_ = key
		}
	})
	b.Run("Use jwk.FromRaw", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var raw ecdsa.PublicKey
			raw.Curve = secp256k1.S256()
			raw.X = &big.Int{}
			raw.Y = &big.Int{}
			raw.X.SetBytes(x)
			raw.Y.SetBytes(y)

			key, err := jwk.FromRaw(&raw)
			if err != nil {
				panic(err)
			}
			_ = key
		}
	})
}
