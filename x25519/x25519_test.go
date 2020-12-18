package x25519

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewKeyFromSeed(t *testing.T) {
	// These test vectors are from RFC7748 Section 6.1
	const alicePrivHex = `77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a`
	const alicePubHex = `8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a`
	const bobPrivHex = `5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb`
	const bobPubHex = `de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f`

	alicePrivSeed, err := hex.DecodeString(alicePrivHex)
	if !assert.NoError(t, err, `alice seed decoded`) {
		return
	}
	alicePriv, err := NewKeyFromSeed(alicePrivSeed)
	if !assert.NoError(t, err, `alice private key`) {
		return
	}

	alicePub := alicePriv.Public().(PublicKey)
	if !assert.Equal(t, hex.EncodeToString(alicePub), alicePubHex, `alice public key`) {
		return
	}

	bobPrivSeed, err := hex.DecodeString(bobPrivHex)
	if !assert.NoError(t, err, `bob seed decoded`) {
		return
	}
	bobPriv, err := NewKeyFromSeed(bobPrivSeed)
	if !assert.NoError(t, err, `bob private key`) {
		return
	}

	bobPub := bobPriv.Public().(PublicKey)
	if !assert.Equal(t, hex.EncodeToString(bobPub), bobPubHex, `bob public key`) {
		return
	}
}
