package jwebb_test

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwe/jwebb"
	"github.com/stretchr/testify/require"
)

func TestNewECDHESKeyGenerator(t *testing.T) {
	t.Run("ecdh P-256", func(t *testing.T) {
		priv, err := ecdh.P256().GenerateKey(rand.Reader)
		require.NoError(t, err)

		gen, err := jwebb.NewECDHESKeyGenerator(priv.PublicKey())
		require.NoError(t, err)
		require.NotNil(t, gen)

		derived, epk, err := gen.GenerateECDHES("A128GCM", 16, nil, nil)
		require.NoError(t, err)
		require.Len(t, derived, 16)
		require.NotNil(t, epk)
	})

	t.Run("ecdh P-384", func(t *testing.T) {
		priv, err := ecdh.P384().GenerateKey(rand.Reader)
		require.NoError(t, err)

		gen, err := jwebb.NewECDHESKeyGenerator(priv.PublicKey())
		require.NoError(t, err)

		derived, epk, err := gen.GenerateECDHES("A256GCM", 32, nil, nil)
		require.NoError(t, err)
		require.Len(t, derived, 32)
		require.NotNil(t, epk)
	})

	t.Run("ecdh P-521", func(t *testing.T) {
		priv, err := ecdh.P521().GenerateKey(rand.Reader)
		require.NoError(t, err)

		gen, err := jwebb.NewECDHESKeyGenerator(priv.PublicKey())
		require.NoError(t, err)

		derived, epk, err := gen.GenerateECDHES("A256GCM", 32, nil, nil)
		require.NoError(t, err)
		require.Len(t, derived, 32)
		require.NotNil(t, epk)
	})

	t.Run("ecdh X25519", func(t *testing.T) {
		priv, err := ecdh.X25519().GenerateKey(rand.Reader)
		require.NoError(t, err)

		gen, err := jwebb.NewECDHESKeyGenerator(priv.PublicKey())
		require.NoError(t, err)

		derived, epk, err := gen.GenerateECDHES("A128GCM", 16, nil, nil)
		require.NoError(t, err)
		require.Len(t, derived, 16)
		require.NotNil(t, epk)
	})

	t.Run("ecdsa P-256", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		gen, err := jwebb.NewECDHESKeyGenerator(&priv.PublicKey)
		require.NoError(t, err)

		derived, epk, err := gen.GenerateECDHES("A128GCM", 16, nil, nil)
		require.NoError(t, err)
		require.Len(t, derived, 16)
		require.NotNil(t, epk)
	})

	t.Run("ecdh private key extracts public", func(t *testing.T) {
		priv, err := ecdh.P256().GenerateKey(rand.Reader)
		require.NoError(t, err)

		gen, err := jwebb.NewECDHESKeyGenerator(priv)
		require.NoError(t, err)
		require.NotNil(t, gen)
	})

	t.Run("ecdsa private key extracts public", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		gen, err := jwebb.NewECDHESKeyGenerator(priv)
		require.NoError(t, err)
		require.NotNil(t, gen)
	})

	t.Run("unsupported key type", func(t *testing.T) {
		_, err := jwebb.NewECDHESKeyGenerator([]byte("not a key"))
		require.Error(t, err)
	})
}

func TestNewECDHESKeyDeriver(t *testing.T) {
	t.Run("ecdh P-256", func(t *testing.T) {
		priv, err := ecdh.P256().GenerateKey(rand.Reader)
		require.NoError(t, err)

		deriver, err := jwebb.NewECDHESKeyDeriver(priv)
		require.NoError(t, err)
		require.NotNil(t, deriver)
	})

	t.Run("ecdh X25519", func(t *testing.T) {
		priv, err := ecdh.X25519().GenerateKey(rand.Reader)
		require.NoError(t, err)

		deriver, err := jwebb.NewECDHESKeyDeriver(priv)
		require.NoError(t, err)
		require.NotNil(t, deriver)
	})

	t.Run("ecdsa P-256", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		deriver, err := jwebb.NewECDHESKeyDeriver(priv)
		require.NoError(t, err)
		require.NotNil(t, deriver)
	})

	t.Run("already implements ECDHESKeyDeriver", func(t *testing.T) {
		priv, err := ecdh.P256().GenerateKey(rand.Reader)
		require.NoError(t, err)

		// First wrap it, then pass the wrapper — should return as-is
		deriver, err := jwebb.NewECDHESKeyDeriver(priv)
		require.NoError(t, err)

		deriver2, err := jwebb.NewECDHESKeyDeriver(deriver)
		require.NoError(t, err)
		require.NotNil(t, deriver2)
	})

	t.Run("unsupported key type", func(t *testing.T) {
		_, err := jwebb.NewECDHESKeyDeriver([]byte("not a key"))
		require.Error(t, err)
	})
}

func TestECDHESGenerateAndDerive(t *testing.T) {
	// End-to-end: generate with public key, derive with private key, keys must match
	t.Run("ecdh P-256 round-trip", func(t *testing.T) {
		priv, err := ecdh.P256().GenerateKey(rand.Reader)
		require.NoError(t, err)

		gen, err := jwebb.NewECDHESKeyGenerator(priv.PublicKey())
		require.NoError(t, err)

		derivedEnc, epk, err := gen.GenerateECDHES("A128GCM", 16, testAPU, testAPV)
		require.NoError(t, err)

		deriver, err := jwebb.NewECDHESKeyDeriver(priv)
		require.NoError(t, err)

		derivedDec, err := deriver.DeriveECDHES("A128GCM", 16, epk, testAPU, testAPV)
		require.NoError(t, err)

		require.Equal(t, derivedEnc, derivedDec)
	})

	t.Run("ecdh X25519 round-trip", func(t *testing.T) {
		priv, err := ecdh.X25519().GenerateKey(rand.Reader)
		require.NoError(t, err)

		gen, err := jwebb.NewECDHESKeyGenerator(priv.PublicKey())
		require.NoError(t, err)

		derivedEnc, epk, err := gen.GenerateECDHES("A256GCM", 32, testAPU, testAPV)
		require.NoError(t, err)

		deriver, err := jwebb.NewECDHESKeyDeriver(priv)
		require.NoError(t, err)

		derivedDec, err := deriver.DeriveECDHES("A256GCM", 32, epk, testAPU, testAPV)
		require.NoError(t, err)

		require.Equal(t, derivedEnc, derivedDec)
	})

	t.Run("ecdsa P-256 round-trip", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		gen, err := jwebb.NewECDHESKeyGenerator(&priv.PublicKey)
		require.NoError(t, err)

		derivedEnc, epk, err := gen.GenerateECDHES("A128GCM", 16, testAPU, testAPV)
		require.NoError(t, err)

		deriver, err := jwebb.NewECDHESKeyDeriver(priv)
		require.NoError(t, err)

		derivedDec, err := deriver.DeriveECDHES("A128GCM", 16, epk, testAPU, testAPV)
		require.NoError(t, err)

		require.Equal(t, derivedEnc, derivedDec)
	})
}

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

func TestNewECDHESKeyGeneratorRejectsUnsafeECDSACurves(t *testing.T) {
	t.Run("tampered curve", func(t *testing.T) {
		pub := &ecdsa.PublicKey{
			Curve: unsafeCurve{},
			X:     big.NewInt(1),
			Y:     big.NewInt(1),
		}
		_, err := jwebb.NewECDHESKeyGenerator(pub)
		require.Error(t, err, "attacker-controlled curve must not be accepted")
	})

	t.Run("generic CurveParams path", func(t *testing.T) {
		// A valid P-256 point with Curve set to the generic big-int
		// implementation. crypto/ecdh uses identity matching on named
		// curves, so the slow generic path is rejected even though the
		// point is mathematically on P-256.
		valid, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		pub := &ecdsa.PublicKey{
			Curve: elliptic.P256().Params(),
			X:     valid.X,
			Y:     valid.Y,
		}
		_, err = jwebb.NewECDHESKeyGenerator(pub)
		require.Error(t, err, "generic CurveParams path must not be accepted")
	})

	t.Run("unsupported stdlib curve P-224", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		require.NoError(t, err)
		_, err = jwebb.NewECDHESKeyGenerator(&priv.PublicKey)
		require.Error(t, err, "P-224 is not a valid JOSE ECDH-ES curve")
	})

	t.Run("nil X and Y", func(t *testing.T) {
		pub := &ecdsa.PublicKey{Curve: elliptic.P256()}
		_, err := jwebb.NewECDHESKeyGenerator(pub)
		require.Error(t, err, "nil X/Y must not be accepted")
	})
}
