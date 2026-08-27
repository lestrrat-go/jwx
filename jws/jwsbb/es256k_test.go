//go:build jwx_es256k

package jwsbb_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	dsigsecp256k1 "github.com/lestrrat-go/dsig-secp256k1"
	"github.com/lestrrat-go/jwx/v3/jws/jwsbb"
	"github.com/stretchr/testify/require"
)

func TestES256KWithSecp256k1(t *testing.T) {
	payload := []byte("hello world")

	// Generate a secp256k1 key (the actual curve ES256K should use)
	secp256k1Key, err := ecdsa.GenerateKey(dsigsecp256k1.Curve(), rand.Reader)
	require.NoError(t, err, "secp256k1 key generation should succeed")

	// Test Sign with ES256K algorithm using secp256k1 key
	signature, err := jwsbb.Sign(secp256k1Key, "ES256K", payload, nil)
	require.NoError(t, err, "ES256K signing should not error")

	// Test Verify with ES256K algorithm using secp256k1 key
	err = jwsbb.Verify(&secp256k1Key.PublicKey, "ES256K", payload, signature)
	require.NoError(t, err, "ES256K verification should succeed")

	// Verify that a tampered signature fails
	tamperedSig := make([]byte, len(signature))
	copy(tamperedSig, signature)
	if len(tamperedSig) > 0 {
		tamperedSig[0] ^= 1 // flip a bit
	}
	err = jwsbb.Verify(&secp256k1Key.PublicKey, "ES256K", payload, tamperedSig)
	require.Error(t, err, "ES256K verification should fail for tampered signature")
}
