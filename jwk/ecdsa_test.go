package jwk_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"math/big"
	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/base64"
	"github.com/lestrrat-go/jwx/v4/jwk"
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

// TestECDSAInvalidPointsRejectedOnParse asserts that ParseKey / Parse are
// the trust boundary for externally supplied ECDSA JWKs: off-curve (x, y)
// and the identity point (0, 0) are rejected at parse time, not deferred
// to a later Validate() / Export call. The defaultParseKey path calls
// key.Validate() after UnmarshalKey, so invalid points never escape as a
// Key value.
func TestECDSAInvalidPointsRejectedOnParse(t *testing.T) {
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

			_, err := jwk.ParseKey[jwk.Key](body)
			require.Error(t, err, `ParseKey must reject invalid ECDSA point at parse time`)
			require.True(t, jwk.IsKeyValidationError(err), `ParseKey error must unwrap to a key-validation error: %v`, err)

			// The Set-level entry point funnels individual keys through
			// defaultParseKey too, so the same body wrapped in a JWKS must
			// also be rejected.
			setBody := []byte(`{"keys":[` + string(body) + `]}`)
			_, err = jwk.Parse(setBody)
			require.Error(t, err, `jwk.Parse must reject a JWKS containing an invalid ECDSA point`)
		})
	}

	t.Run("valid point round-trips", func(t *testing.T) {
		body := []byte(`{
			"kty": "EC",
			"crv": "P-256",
			"x": "AYwhwiE1hXWdfwu-HlBSsY5Chxycu-LyE6WsZ_w2DO4",
			"y": "zumemGclMFkimMsKMXlLdKYWtLle58e4N9hDPcN7lig"
		}`)
		key, err := jwk.ParseKey[jwk.Key](body)
		require.NoError(t, err, `ParseKey on a valid P-256 key should succeed`)
		require.NoError(t, key.Validate(), `Validate on a valid P-256 key should succeed`)
		_, err = jwk.Export[*ecdsa.PublicKey](key)
		require.NoError(t, err, `Export on a valid P-256 key should succeed`)
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
		_, err := jwk.Import[jwk.Key](bad)
		require.Error(t, err, `jwk.Import must reject an off-curve ecdsa.PublicKey`)
		require.ErrorIs(t, err, jwk.ImportError(), `Import error should be classified as jwk.ImportError`)
		require.True(t, errors.Is(err, jwk.ImportError()), `errors.Is should match jwk.ImportError`)
	})

	t.Run("identity public key", func(t *testing.T) {
		bad := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     big.NewInt(0),
			Y:     big.NewInt(0),
		}
		_, err := jwk.Import[jwk.Key](bad)
		require.Error(t, err, `jwk.Import must reject the identity point`)
		require.ErrorIs(t, err, jwk.ImportError(), `Import error should be classified as jwk.ImportError`)
		require.True(t, errors.Is(err, jwk.ImportError()), `errors.Is should match jwk.ImportError`)
	})
}
