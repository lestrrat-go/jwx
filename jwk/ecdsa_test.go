package jwk_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/lestrrat-go/jwx/v3/internal/base64"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"
)

// ecdsaPointJWK builds a JWK JSON body with the given curve name and raw
// x/y coordinates. It zero-pads each coordinate to the curve byte size so
// length validation in ecdsaValidateKey does not reject the input before
// the point-on-curve check runs.
func ecdsaPointJWK(t *testing.T, crv elliptic.Curve, crvName string, x, y *big.Int) []byte {
	t.Helper()
	size := (crv.Params().BitSize + 7) / 8
	xb := make([]byte, size)
	yb := make([]byte, size)
	x.FillBytes(xb)
	y.FillBytes(yb)
	body := `{"kty":"EC","crv":"` + crvName + `","x":"` + base64.EncodeToString(xb) + `","y":"` + base64.EncodeToString(yb) + `"}`
	return []byte(body)
}

// TestECDSAInvalidPointsRejectedOnUse covers JWK-003: ParseKey stores raw
// x/y bytes without curve checks, but any downstream use of the key —
// Export (which constructs a *ecdsa.PublicKey) or an explicit Validate()
// — must refuse points that are not on the declared curve and the
// identity point (0, 0). Without validation, these feed invalid-curve
// attacks to downstream ECDSA/ECDH consumers.
func TestECDSAInvalidPointsRejectedOnUse(t *testing.T) {
	cases := []struct {
		name string
		x, y *big.Int
	}{
		{"identity point", big.NewInt(0), big.NewInt(0)},
		// (1, 1) is overwhelmingly unlikely to be on P-256.
		{"off-curve point", big.NewInt(1), big.NewInt(1)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := ecdsaPointJWK(t, elliptic.P256(), "P-256", tc.x, tc.y)
			key, err := jwk.ParseKey(body)
			require.NoError(t, err, `ParseKey stores raw bytes; it does not run curve checks yet`)

			require.Error(t, key.Validate(), `Validate must reject invalid ECDSA point`)

			var pub ecdsa.PublicKey
			require.Error(t, jwk.Export(key, &pub), `Export to *ecdsa.PublicKey must reject invalid ECDSA point`)
		})
	}

	t.Run("valid point round-trips", func(t *testing.T) {
		body := []byte(`{
			"kty": "EC",
			"crv": "P-256",
			"x": "AYwhwiE1hXWdfwu-HlBSsY5Chxycu-LyE6WsZ_w2DO4",
			"y": "zumemGclMFkimMsKMXlLdKYWtLle58e4N9hDPcN7lig"
		}`)
		key, err := jwk.ParseKey(body)
		require.NoError(t, err, `ParseKey on a valid P-256 key should succeed`)
		require.NoError(t, key.Validate(), `Validate on a valid P-256 key should succeed`)
		var pub ecdsa.PublicKey
		require.NoError(t, jwk.Export(key, &pub), `Export on a valid P-256 key should succeed`)
	})
}

// TestECDSAImportRejectsInvalidPoints covers the Import(*ecdsa.PublicKey)
// entry point, which previously accepted any non-nil X/Y without curve
// membership checks.
func TestECDSAImportRejectsInvalidPoints(t *testing.T) {
	t.Run("off-curve public key", func(t *testing.T) {
		bad := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     big.NewInt(1),
			Y:     big.NewInt(1),
		}
		_, err := jwk.Import(bad)
		require.Error(t, err, `jwk.Import must reject an off-curve ecdsa.PublicKey`)
	})

	t.Run("identity public key", func(t *testing.T) {
		bad := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     big.NewInt(0),
			Y:     big.NewInt(0),
		}
		_, err := jwk.Import(bad)
		require.Error(t, err, `jwk.Import must reject the identity point`)
	})
}
