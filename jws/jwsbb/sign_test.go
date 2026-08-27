package jwsbb_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/lestrrat-go/dsig"
	"github.com/stretchr/testify/require"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws/jwsbb"
)

// TestSignCustomECDSAFamilyAlgorithmIgnoresCurveCheck simulates what an
// extension module such as github.com/jwx-go/es256k/v4 does: it registers a
// non-built-in ECDSA-family dsig algorithm and a matching JWS algorithm name,
// without going through the three RFC 7518 built-ins (ES256/ES384/ES512).
// jwsbb's ECDSA curve-binding check keys its table on the built-in dsig
// algorithm names, so this registration must sign successfully with a key on
// any curve — the new check must not fire for it.
func TestSignCustomECDSAFamilyAlgorithmIgnoresCurveCheck(t *testing.T) {
	const jwsAlgName = "ES256TEST"
	const dsigAlgName = "ECDSA_WITH_TEST_CURVE_AND_SHA256"

	require.NoError(t, dsig.RegisterAlgorithm(dsigAlgName, dsig.AlgorithmInfo{
		Family: dsig.ECDSA,
		Meta:   dsig.ECDSAFamilyMeta{Hash: crypto.SHA256},
	}))
	defer func() {
		require.NoError(t, dsig.UnregisterAlgorithm(dsigAlgName))
	}()

	jwsAlg := jwa.NewSignatureAlgorithm(jwsAlgName)
	require.NoError(t, jwa.RegisterSignatureAlgorithm(jwsAlg))
	defer jwa.UnregisterSignatureAlgorithm(jwsAlg)

	require.NoError(t, jwsbb.RegisterDsigAlgorithm(jwsAlgName, dsigAlgName))

	// P-384 paired with an algorithm whose name suggests P-256: this is
	// exactly the shape RFC 7518 §3.4 forbids for the built-in ES256, but
	// ES256TEST is not one of the three built-ins, so the table lookup
	// misses and the key passes through untouched.
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	_, err = jwsbb.Sign(key, jwsAlgName, []byte("hello"), rand.Reader)
	require.NoError(t, err)
}
