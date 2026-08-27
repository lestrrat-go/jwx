package jwsbb_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"math/big"
	"testing"

	"github.com/lestrrat-go/dsig"
	"github.com/stretchr/testify/require"

	jwsbb "github.com/lestrrat-go/jwx/v4/jws/internal/jwsbb"
)

// nilParamsCurve is an elliptic.Curve whose Params() returns nil, standing in
// for a custom curve implementation that does not fill in CurveParams.
// Stdlib curves never do this; this exercises the documented fail-open
// contract of RequireECDSACurve for that case.
type nilParamsCurve struct{}

func (nilParamsCurve) Params() *elliptic.CurveParams { return nil }
func (nilParamsCurve) IsOnCurve(_, _ *big.Int) bool  { return false }
func (nilParamsCurve) Add(_, _, _, _ *big.Int) (*big.Int, *big.Int) {
	return nil, nil
}
func (nilParamsCurve) Double(_, _ *big.Int) (*big.Int, *big.Int) {
	return nil, nil
}
func (nilParamsCurve) ScalarMult(_, _ *big.Int, _ []byte) (*big.Int, *big.Int) {
	return nil, nil
}
func (nilParamsCurve) ScalarBaseMult(_ []byte) (*big.Int, *big.Int) {
	return nil, nil
}

// nonECDSASigner is a crypto.Signer whose Public() does not return an ECDSA
// public key. RequireECDSACurve must treat it the same as a key with no
// discoverable curve: nil error, allowed through.
type nonECDSASigner struct{}

func (nonECDSASigner) Public() crypto.PublicKey                                  { return "not-a-key" }
func (nonECDSASigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) { return nil, nil }

// ecdsaCryptoSigner wraps an *ecdsa.PrivateKey behind crypto.Signer, mirroring
// the shape an HSM/KMS-backed signer takes.
type ecdsaCryptoSigner struct {
	raw *ecdsa.PrivateKey
}

func (s *ecdsaCryptoSigner) Public() crypto.PublicKey { return &s.raw.PublicKey }
func (s *ecdsaCryptoSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.raw.Sign(rand, digest, opts)
}

func generateECDSAKey(t *testing.T, crv elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(crv, rand.Reader)
	require.NoError(t, err)
	return key
}

func TestRequireECDSACurve(t *testing.T) {
	t.Parallel()

	p256Key := generateECDSAKey(t, elliptic.P256())
	p384Key := generateECDSAKey(t, elliptic.P384())
	p521Key := generateECDSAKey(t, elliptic.P521())

	t.Run("built-in dsig algorithm x curve matrix", func(t *testing.T) {
		t.Parallel()

		curves := []struct {
			name string
			key  *ecdsa.PrivateKey
			crv  elliptic.Curve
		}{
			{"P-256", p256Key, elliptic.P256()},
			{"P-384", p384Key, elliptic.P384()},
			{"P-521", p521Key, elliptic.P521()},
		}
		dsigAlgs := []struct {
			jwsAlg  string
			dsigAlg string
			want    elliptic.Curve
		}{
			{"ES256", dsig.ECDSAWithP256AndSHA256, elliptic.P256()},
			{"ES384", dsig.ECDSAWithP384AndSHA384, elliptic.P384()},
			{"ES512", dsig.ECDSAWithP521AndSHA512, elliptic.P521()},
		}

		for _, da := range dsigAlgs {
			for _, c := range curves {
				match := c.crv == da.want
				name := da.jwsAlg + "/" + c.name
				t.Run(name, func(t *testing.T) {
					t.Parallel()
					err := jwsbb.RequireECDSACurve(da.jwsAlg, da.dsigAlg, c.key)
					if match {
						require.NoError(t, err)
						return
					}
					require.Error(t, err)
					require.Contains(t, err.Error(), "ECDSA curve mismatch")
				})
			}
		}
	})

	t.Run("nil key returns nil error", func(t *testing.T) {
		t.Parallel()
		err := jwsbb.RequireECDSACurve("ES256", dsig.ECDSAWithP256AndSHA256, nil)
		require.NoError(t, err)
	})

	t.Run("key with nil curve returns nil error", func(t *testing.T) {
		t.Parallel()
		err := jwsbb.RequireECDSACurve("ES256", dsig.ECDSAWithP256AndSHA256, &ecdsa.PublicKey{})
		require.NoError(t, err)
	})

	t.Run("unrelated dsig algorithm returns nil error", func(t *testing.T) {
		t.Parallel()
		err := jwsbb.RequireECDSACurve("ES256TEST", "ECDSA_WITH_TEST_CURVE_AND_SHA256", p384Key)
		require.NoError(t, err)
	})

	t.Run("crypto.Signer with non-ECDSA public key returns nil error", func(t *testing.T) {
		t.Parallel()
		err := jwsbb.RequireECDSACurve("ES256", dsig.ECDSAWithP256AndSHA256, nonECDSASigner{})
		require.NoError(t, err)
	})

	t.Run("crypto.Signer wrapping a matching ECDSA key is accepted", func(t *testing.T) {
		t.Parallel()
		err := jwsbb.RequireECDSACurve("ES256", dsig.ECDSAWithP256AndSHA256, &ecdsaCryptoSigner{raw: p256Key})
		require.NoError(t, err)
	})

	t.Run("crypto.Signer wrapping a mismatched ECDSA key is rejected", func(t *testing.T) {
		t.Parallel()
		err := jwsbb.RequireECDSACurve("ES256", dsig.ECDSAWithP256AndSHA256, &ecdsaCryptoSigner{raw: p521Key})
		require.Error(t, err)
		require.Contains(t, err.Error(), "ECDSA curve mismatch")
	})

	t.Run("value forms of the key are accepted", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, jwsbb.RequireECDSACurve("ES256", dsig.ECDSAWithP256AndSHA256, *p256Key))
		require.NoError(t, jwsbb.RequireECDSACurve("ES256", dsig.ECDSAWithP256AndSHA256, p256Key.PublicKey))
		require.NoError(t, jwsbb.RequireECDSACurve("ES256", dsig.ECDSAWithP256AndSHA256, &p256Key.PublicKey))
	})

	t.Run("curve built from Params() falls back to name comparison", func(t *testing.T) {
		t.Parallel()
		// A key whose Curve is elliptic.P256().Params() rather than the
		// elliptic.P256() singleton must still be accepted: pointer identity
		// fails, but the curve name ("P-256") still matches.
		key := &ecdsa.PublicKey{
			Curve: elliptic.P256().Params(),
			X:     p256Key.PublicKey.X,
			Y:     p256Key.PublicKey.Y,
		}
		err := jwsbb.RequireECDSACurve("ES256", dsig.ECDSAWithP256AndSHA256, key)
		require.NoError(t, err)
	})

	t.Run("key with a curve reporting nil Params returns nil error", func(t *testing.T) {
		t.Parallel()
		// RequireECDSACurve's doc comment promises nil, never an error,
		// whenever the binding cannot be established. A curve implementation
		// that returns nil from Params() falls into that case, even though
		// no stdlib curve does this in practice.
		key := &ecdsa.PublicKey{
			Curve: nilParamsCurve{},
			X:     p256Key.PublicKey.X,
			Y:     p256Key.PublicKey.Y,
		}
		err := jwsbb.RequireECDSACurve("ES256", dsig.ECDSAWithP256AndSHA256, key)
		require.NoError(t, err)
	})
}
