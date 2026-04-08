package jwebb_test

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
