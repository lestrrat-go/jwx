//go:build jwx_dilithium
// +build jwx_dilithium

package jws_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode2"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/cloudflare/circl/sign/dilithium/mode5"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDilithiumSignAndVerify verifies that the dilithium signing and verification process works
func TestDilithiumSignAndVerify(t *testing.T) {
	t.Parallel()

	payload := []byte("Hello, Dilithium!")

	testcases := []struct {
		name      string
		algorithm jwa.SignatureAlgorithm
		keygen    func() (interface{}, interface{}, error)
		badKey    func() interface{}
	}{
		{
			name:      "CRYDI2",
			algorithm: jwa.CRYDI2(),
			keygen: func() (interface{}, interface{}, error) {
				pubKey, privKey, err := mode2.GenerateKey(rand.Reader)
				return &pubKey, &privKey, err
			},
			badKey: func() interface{} {
				pubKey, _, _ := mode3.GenerateKey(rand.Reader)
				return &pubKey
			},
		},
		{
			name:      "CRYDI3",
			algorithm: jwa.CRYDI3(),
			keygen: func() (interface{}, interface{}, error) {
				pubKey, privKey, err := mode3.GenerateKey(rand.Reader)
				return &pubKey, &privKey, err
			},
			badKey: func() interface{} {
				pubKey, _, _ := mode5.GenerateKey(rand.Reader)
				return &pubKey
			},
		},
		{
			name:      "CRYDI5",
			algorithm: jwa.CRYDI5(),
			keygen: func() (interface{}, interface{}, error) {
				pubKey, privKey, err := mode5.GenerateKey(rand.Reader)
				return &pubKey, &privKey, err
			},
			badKey: func() interface{} {
				pubKey, _, _ := mode2.GenerateKey(rand.Reader)
				return &pubKey
			},
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Generate keys
			pubKey, privKey, err := tc.keygen()
			require.NoError(t, err, "failed to generate key pair")

			// 二重ポインタになっているので、値を取り出す
			privKeyPtr, ok := privKey.(*mode2.PrivateKey)
			if ok {
				// Full JWS signing process
				signed, err := jws.Sign(payload, jws.WithKey(tc.algorithm, privKeyPtr))
				require.NoError(t, err, "failed to sign payload")

				// Verify the signature
				pubKeyPtr := pubKey.(*mode2.PublicKey)
				verified, err := jws.Verify(signed, jws.WithKey(tc.algorithm, pubKeyPtr))
				require.NoError(t, err, "failed to verify signature")
				assert.Equal(t, payload, verified, "payload mismatch after verification")

				// Test verification with incorrect key
				badKey := tc.badKey()
				_, err = jws.Verify(signed, jws.WithKey(tc.algorithm, badKey))
				assert.Error(t, err, "verification with incorrect key should fail")

				// Test tampering detection
				tampered := make([]byte, len(signed))
				copy(tampered, signed)
				// Tamper with the payload (changing a byte in the middle)
				if len(tampered) > 0 {
					midpoint := len(tampered) / 2
					tampered[midpoint] ^= 0xFF // Flip bits in a byte
				}

				_, err = jws.Verify(tampered, jws.WithKey(tc.algorithm, pubKeyPtr))
				assert.Error(t, err, "verification of tampered message should fail")
			} else if privKeyPtr, ok := privKey.(*mode3.PrivateKey); ok {
				// Full JWS signing process
				signed, err := jws.Sign(payload, jws.WithKey(tc.algorithm, privKeyPtr))
				require.NoError(t, err, "failed to sign payload")

				// Verify the signature
				pubKeyPtr := pubKey.(*mode3.PublicKey)
				verified, err := jws.Verify(signed, jws.WithKey(tc.algorithm, pubKeyPtr))
				require.NoError(t, err, "failed to verify signature")
				assert.Equal(t, payload, verified, "payload mismatch after verification")

				// Test verification with incorrect key
				badKey := tc.badKey()
				_, err = jws.Verify(signed, jws.WithKey(tc.algorithm, badKey))
				assert.Error(t, err, "verification with incorrect key should fail")

				// Test tampering detection
				tampered := make([]byte, len(signed))
				copy(tampered, signed)
				// Tamper with the payload (changing a byte in the middle)
				if len(tampered) > 0 {
					midpoint := len(tampered) / 2
					tampered[midpoint] ^= 0xFF // Flip bits in a byte
				}

				_, err = jws.Verify(tampered, jws.WithKey(tc.algorithm, pubKeyPtr))
				assert.Error(t, err, "verification of tampered message should fail")
			} else if privKeyPtr, ok := privKey.(*mode5.PrivateKey); ok {
				// Full JWS signing process
				signed, err := jws.Sign(payload, jws.WithKey(tc.algorithm, privKeyPtr))
				require.NoError(t, err, "failed to sign payload")

				// Verify the signature
				pubKeyPtr := pubKey.(*mode5.PublicKey)
				verified, err := jws.Verify(signed, jws.WithKey(tc.algorithm, pubKeyPtr))
				require.NoError(t, err, "failed to verify signature")
				assert.Equal(t, payload, verified, "payload mismatch after verification")

				// Test verification with incorrect key
				badKey := tc.badKey()
				_, err = jws.Verify(signed, jws.WithKey(tc.algorithm, badKey))
				assert.Error(t, err, "verification with incorrect key should fail")

				// Test tampering detection
				tampered := make([]byte, len(signed))
				copy(tampered, signed)
				// Tamper with the payload (changing a byte in the middle)
				if len(tampered) > 0 {
					midpoint := len(tampered) / 2
					tampered[midpoint] ^= 0xFF // Flip bits in a byte
				}

				_, err = jws.Verify(tampered, jws.WithKey(tc.algorithm, pubKeyPtr))
				assert.Error(t, err, "verification of tampered message should fail")
			}
		})
	}
}

// TestDilithiumSignerVerifier tests the direct signer and verifier functionality
func TestDilithiumSignerVerifier(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name      string
		algorithm jwa.SignatureAlgorithm
		keygen    func() (interface{}, interface{}, error)
	}{
		{
			name:      "CRYDI2",
			algorithm: jwa.CRYDI2(),
			keygen: func() (interface{}, interface{}, error) {
				pubKey, privKey, err := mode2.GenerateKey(rand.Reader)
				return pubKey, privKey, err
			},
		},
		{
			name:      "CRYDI3",
			algorithm: jwa.CRYDI3(),
			keygen: func() (interface{}, interface{}, error) {
				pubKey, privKey, err := mode3.GenerateKey(rand.Reader)
				return pubKey, privKey, err
			},
		},
		{
			name:      "CRYDI5",
			algorithm: jwa.CRYDI5(),
			keygen: func() (interface{}, interface{}, error) {
				pubKey, privKey, err := mode5.GenerateKey(rand.Reader)
				return pubKey, privKey, err
			},
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			payload := []byte("Hello, Dilithium!")
			pubKey, privKey, err := tc.keygen()
			require.NoError(t, err, "failed to generate key pair")

			// Sign with full JWS process
			signed, err := jws.Sign(payload, jws.WithKey(tc.algorithm, privKey))
			require.NoError(t, err, "failed to sign payload")

			// Parse the JWS message
			msg, err := jws.Parse(signed)
			require.NoError(t, err, "failed to parse JWS message")

			// Verify the signature exists in the parsed message
			require.Equal(t, 1, len(msg.Signatures()), "should have one signature")

			// Verify the algorithm in the header
			var alg jwa.SignatureAlgorithm
			err = msg.Signatures()[0].ProtectedHeaders().Get(jws.AlgorithmKey, &alg)
			require.NoError(t, err, "failed to get algorithm from headers")
			assert.Equal(t, tc.algorithm, alg, "algorithm in header should match")

			// Verify the decoded payload
			decodedPayload := msg.Payload()
			assert.Equal(t, payload, decodedPayload, "payload should match")

			// Verify the signature through the JWS API
			verified, err := jws.Verify(signed, jws.WithKey(tc.algorithm, pubKey))
			require.NoError(t, err, "failed to verify signature")
			assert.Equal(t, payload, verified, "payload mismatch after verification")
		})
	}
}

// TestDilithiumErrorCases tests error conditions in the dilithium signing and verification process
func TestDilithiumErrorCases(t *testing.T) {
	t.Parallel()

	// Test cases for error conditions
	testcases := []struct {
		name      string
		algorithm jwa.SignatureAlgorithm
		keygen    func() (interface{}, interface{})
		testFunc  func(t *testing.T, alg jwa.SignatureAlgorithm, pub, priv interface{})
	}{
		{
			name:      "CRYDI2 with nil keys",
			algorithm: jwa.CRYDI2(),
			keygen: func() (interface{}, interface{}) {
				return nil, nil
			},
			testFunc: func(t *testing.T, alg jwa.SignatureAlgorithm, pub, priv interface{}) {
				payload := []byte("Test payload")

				// Sign with nil key - should fail
				_, err := jws.Sign(payload, jws.WithKey(alg, priv))
				require.Error(t, err, "signing with nil key should fail")
			},
		},
		{
			name:      "CRYDI2 with wrong key type",
			algorithm: jwa.CRYDI2(),
			keygen: func() (interface{}, interface{}) {
				// Use string as wrong key type
				return "wrong public key", "wrong private key"
			},
			testFunc: func(t *testing.T, alg jwa.SignatureAlgorithm, pub, priv interface{}) {
				payload := []byte("Test payload")

				// Sign with wrong key type - should fail
				_, err := jws.Sign(payload, jws.WithKey(alg, priv))
				require.Error(t, err, "signing with wrong key type should fail")
			},
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pub, priv := tc.keygen()
			tc.testFunc(t, tc.algorithm, pub, priv)
		})
	}
}

// TestDilithiumWithVariousPayloadSizes tests dilithium with different payload sizes
func TestDilithiumWithVariousPayloadSizes(t *testing.T) {
	t.Parallel()

	// Test different payload sizes to ensure the algorithm works properly in all cases
	payloadSizes := []int{0, 1, 64, 256, 1024, 4096}

	pubKey, privKey, err := mode2.GenerateKey(rand.Reader)
	require.NoError(t, err, "failed to generate key pair")

	for _, size := range payloadSizes {
		t.Run(fmt.Sprintf("PayloadSize=%d", size), func(t *testing.T) {
			t.Parallel()

			// Generate random payload of specified size
			payload := make([]byte, size)
			if size > 0 {
				_, err := rand.Read(payload)
				require.NoError(t, err, "failed to generate random payload")
			}

			signed, err := jws.Sign(payload, jws.WithKey(jwa.CRYDI2(), privKey))
			require.NoError(t, err, "failed to sign payload of size %d", size)

			// Complete JWS verify process
			verified, err := jws.Verify(signed, jws.WithKey(jwa.CRYDI2(), pubKey))
			require.NoError(t, err, "failed to verify signature for payload of size %d", size)
			assert.True(t, bytes.Equal(payload, verified), "payload mismatch after verification")
		})
	}
}

// TestDilithiumMultipleSignatures tests signing and verification with multiple dilithium signatures
func TestDilithiumMultipleSignatures(t *testing.T) {
	t.Parallel()

	payload := []byte("Multi-signature test payload")

	// Generate keys for different algorithms
	pubKey2, privKey2, err := mode2.GenerateKey(rand.Reader)
	require.NoError(t, err, "failed to generate CRYDI2 key pair")

	pubKey3, privKey3, err := mode3.GenerateKey(rand.Reader)
	require.NoError(t, err, "failed to generate CRYDI3 key pair")

	pubKey5, privKey5, err := mode5.GenerateKey(rand.Reader)
	require.NoError(t, err, "failed to generate CRYDI5 key pair")

	// For multi-signatures, we still need headers for the "kid" field
	hdr2 := jws.NewHeaders()
	err = hdr2.Set("kid", "key-2")
	require.NoError(t, err, "failed to set kid in CRYDI2 headers")

	hdr3 := jws.NewHeaders()
	err = hdr3.Set("kid", "key-3")
	require.NoError(t, err, "failed to set kid in CRYDI3 headers")

	hdr5 := jws.NewHeaders()
	err = hdr5.Set("kid", "key-5")
	require.NoError(t, err, "failed to set kid in CRYDI5 headers")

	// Create multi-signature - JSON形式を使用
	multiSigned, err := jws.Sign(payload,
		jws.WithKey(jwa.CRYDI2(), privKey2, jws.WithProtectedHeaders(hdr2)),
		jws.WithKey(jwa.CRYDI3(), privKey3, jws.WithProtectedHeaders(hdr3)),
		jws.WithKey(jwa.CRYDI5(), privKey5, jws.WithProtectedHeaders(hdr5)),
		jws.WithJSON(), // JSONシリアライゼーションを使用
	)
	require.NoError(t, err, "failed to create multi-signature")

	// Parse the JWS message
	msg, err := jws.Parse(multiSigned)
	require.NoError(t, err, "failed to parse JWS message")

	// Verify we have 3 signatures
	require.Equal(t, 3, len(msg.Signatures()), "should have three signatures")

	// Verify with each key
	verified, err := jws.Verify(multiSigned, jws.WithKey(jwa.CRYDI2(), pubKey2))
	require.NoError(t, err, "failed to verify CRYDI2 signature")
	assert.Equal(t, payload, verified, "payload mismatch after CRYDI2 verification")

	verified, err = jws.Verify(multiSigned, jws.WithKey(jwa.CRYDI3(), pubKey3))
	require.NoError(t, err, "failed to verify CRYDI3 signature")
	assert.Equal(t, payload, verified, "payload mismatch after CRYDI3 verification")

	verified, err = jws.Verify(multiSigned, jws.WithKey(jwa.CRYDI5(), pubKey5))
	require.NoError(t, err, "failed to verify CRYDI5 signature")
	assert.Equal(t, payload, verified, "payload mismatch after CRYDI5 verification")
}
