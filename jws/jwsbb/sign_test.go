package jwsbb_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/lestrrat-go/dsig"
	"github.com/stretchr/testify/require"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws/jwsbb"
)

// TestSignCustomECDSAFamilyAlgorithmIgnoresCurveCheck simulates what an
// extension module does: it registers a non-built-in ECDSA-family dsig
// algorithm, without going through the three RFC 7518 built-ins
// (ES256/ES384/ES512). jwsbb's ECDSA curve-binding check keys its table on
// the built-in dsig algorithm names, so this registration must sign
// successfully with a key on any curve -- the new check must not fire for
// it.
//
// Unlike v4, v3 has no jwsbb.RegisterDsigAlgorithm to remap a JOSE algorithm
// name onto a different dsig algorithm name. jwsbb.Sign falls back to using
// the JOSE name directly as the dsig name when no mapping is registered
// (see jws/jwsbb/jwsbb.go's GetDsigAlgorithm), so the dsig algorithm here is
// registered under the same name as the JOSE algorithm.
func TestSignCustomECDSAFamilyAlgorithmIgnoresCurveCheck(t *testing.T) {
	const algName = "ES256TEST"

	require.NoError(t, dsig.RegisterAlgorithm(algName, dsig.AlgorithmInfo{
		Family: dsig.ECDSA,
		Meta:   dsig.ECDSAFamilyMeta{Hash: crypto.SHA256},
	}))
	defer func() {
		require.NoError(t, dsig.UnregisterAlgorithm(algName))
	}()

	jwsAlg := jwa.NewSignatureAlgorithm(algName)
	jwa.RegisterSignatureAlgorithm(jwsAlg)
	defer jwa.UnregisterSignatureAlgorithm(jwsAlg)

	// P-384 paired with an algorithm whose name suggests P-256: this is
	// exactly the shape RFC 7518 Section 3.4 forbids for the built-in
	// ES256, but ES256TEST is not one of the three built-ins, so the
	// table lookup misses and the key passes through untouched.
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	_, err = jwsbb.Sign(key, algName, []byte("hello"), rand.Reader)
	require.NoError(t, err)
}
