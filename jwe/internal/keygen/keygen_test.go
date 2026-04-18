package keygen_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwe/internal/keygen"
	"github.com/stretchr/testify/require"
)

// unsafeCurve is a minimal elliptic.Curve stub used to prove that an
// attacker-controlled curve on an *ecdsa.PublicKey is rejected at
// conversion time and cannot reach a big-int ScalarMult computation.
type unsafeCurve struct{}

func (unsafeCurve) Params() *elliptic.CurveParams {
	return &elliptic.CurveParams{Name: "unsafe"}
}
func (unsafeCurve) IsOnCurve(_, _ *big.Int) bool { return true }
func (unsafeCurve) Add(_, _, _, _ *big.Int) (*big.Int, *big.Int) {
	return big.NewInt(0), big.NewInt(0)
}
func (unsafeCurve) Double(_, _ *big.Int) (*big.Int, *big.Int) {
	return big.NewInt(0), big.NewInt(0)
}
func (unsafeCurve) ScalarMult(_, _ *big.Int, _ []byte) (*big.Int, *big.Int) {
	return big.NewInt(0), big.NewInt(0)
}
func (unsafeCurve) ScalarBaseMult(_ []byte) (*big.Int, *big.Int) {
	return big.NewInt(0), big.NewInt(0)
}

func TestEcdhesRejectsUnsafeCurves(t *testing.T) {
	t.Run("tampered curve", func(t *testing.T) {
		pub := &ecdsa.PublicKey{
			Curve: unsafeCurve{},
			X:     big.NewInt(1),
			Y:     big.NewInt(1),
		}
		_, err := keygen.Ecdhes("ECDH-ES", "A128GCM", 16, pub, nil, nil)
		require.Error(t, err, "attacker-controlled curve must not be accepted")
	})

	t.Run("generic CurveParams path", func(t *testing.T) {
		valid, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		pub := &ecdsa.PublicKey{
			Curve: elliptic.P256().Params(),
			X:     valid.X,
			Y:     valid.Y,
		}
		_, err = keygen.Ecdhes("ECDH-ES", "A128GCM", 16, pub, nil, nil)
		require.Error(t, err, "generic CurveParams path must not be accepted")
	})

	t.Run("unsupported stdlib curve P-224", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		require.NoError(t, err)
		_, err = keygen.Ecdhes("ECDH-ES", "A128GCM", 16, &priv.PublicKey, nil, nil)
		require.Error(t, err, "P-224 is not a valid JOSE ECDH-ES curve")
	})

	t.Run("nil X and Y", func(t *testing.T) {
		pub := &ecdsa.PublicKey{Curve: elliptic.P256()}
		_, err := keygen.Ecdhes("ECDH-ES", "A128GCM", 16, pub, nil, nil)
		require.Error(t, err, "nil X/Y must not be accepted")
	})
}

func TestEcdhesPositive(t *testing.T) {
	// Sanity: ensure P-256/P-384/P-521 still produce outputs.
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			priv, err := ecdsa.GenerateKey(curve, rand.Reader)
			require.NoError(t, err)
			src, err := keygen.Ecdhes("ECDH-ES", "A128GCM", 16, &priv.PublicKey, nil, nil)
			require.NoError(t, err)
			require.Len(t, src.Bytes(), 16)
		})
	}
}
