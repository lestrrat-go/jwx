package jwkbb_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwk/jwkbb"
	"github.com/stretchr/testify/require"
)

func TestEncodePEM_SingleStdlibKey(t *testing.T) {
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	out, err := jwkbb.EncodePEM(raw)
	require.NoError(t, err)
	block, _ := pem.Decode(out)
	require.NotNil(t, block)
	require.Equal(t, jwkbb.ECPrivateKeyBlockType, block.Type)
}

func TestEncodePEM_VariadicPreservesOrder(t *testing.T) {
	ecRaw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rsaRaw, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	out, err := jwkbb.EncodePEM(ecRaw, rsaRaw)
	require.NoError(t, err)

	first, rest := pem.Decode(out)
	require.NotNil(t, first)
	require.Equal(t, jwkbb.ECPrivateKeyBlockType, first.Type, "first arg should be the first block")

	second, rest2 := pem.Decode(rest)
	require.NotNil(t, second)
	require.Equal(t, jwkbb.PrivateKeyBlockType, second.Type, "second arg should be the second block (PKCS#8)")
	require.Empty(t, rest2, "no trailing bytes expected")
}

func TestEncodePEM_NoArgsError(t *testing.T) {
	_, err := jwkbb.EncodePEM()
	require.Error(t, err)
}

func TestEncodePEM_UnsupportedType(t *testing.T) {
	_, err := jwkbb.EncodePEM("not a key")
	require.Error(t, err)
}

func TestEncodePEM_FailsFastOnUnsupportedMidway(t *testing.T) {
	good, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, err = jwkbb.EncodePEM(good, "not a key")
	require.Error(t, err)
	require.Contains(t, err.Error(), "key #1")
}

func TestRegisterX509Decoder_NilError(t *testing.T) {
	require.NotPanics(t, func() {
		err := jwkbb.RegisterX509Decoder("test-nil-decoder", nil)
		require.Error(t, err)
	})
}

func TestRegisterX509Decoder_NilIdent(t *testing.T) {
	require.NotPanics(t, func() {
		err := jwkbb.RegisterX509Decoder(nil, jwkbb.X509DecodeFunc(func(*pem.Block) (any, error) {
			return nil, errors.New("unused")
		}))
		require.Error(t, err)
	})
}

func TestRegisterX509Encoder_NilError(t *testing.T) {
	require.NotPanics(t, func() {
		err := jwkbb.RegisterX509Encoder("test-nil-encoder", nil)
		require.Error(t, err)
	})
}

func TestRegisterX509Encoder_NilIdent(t *testing.T) {
	require.NotPanics(t, func() {
		err := jwkbb.RegisterX509Encoder(nil, jwkbb.X509EncodeFunc(func(any) (string, []byte, error) {
			return "", nil, errors.New("unused")
		}))
		require.Error(t, err)
	})
}

// A registered custom encoder must be reachable via X509Encoders() and
// produce the bytes it returns.
func TestRegisterX509Encoder_CustomReachableViaIterator(t *testing.T) {
	type fakeKey struct{ tag string }

	const blockType = "FAKE KEY"
	ident := "test-custom-encoder-iter"

	require.NoError(t, jwkbb.RegisterX509Encoder(ident, jwkbb.X509EncodeFunc(func(v any) (string, []byte, error) {
		fk, ok := v.(*fakeKey)
		if !ok {
			return "", nil, fmt.Errorf("not my type")
		}
		return blockType, []byte("custom-der:" + fk.tag), nil
	})))
	t.Cleanup(func() { jwkbb.UnregisterX509Encoder(ident) })

	// Walk the iterator until an encoder claims the fake key.
	var gotType string
	var gotDER []byte
	for e := range jwkbb.X509Encoders() {
		typ, der, err := e.EncodeX509(&fakeKey{tag: "abc"})
		if err != nil {
			continue
		}
		gotType, gotDER = typ, der
		break
	}
	require.Equal(t, blockType, gotType, "custom encoder should be reachable via the registry iterator")
	require.Equal(t, "custom-der:abc", string(gotDER))
}

// Duplicate-ident Register is a no-op.
func TestRegisterX509Encoder_DuplicateIdentIsNoop(t *testing.T) {
	ident := "test-duplicate-encoder"
	enc := jwkbb.X509EncodeFunc(func(any) (string, []byte, error) {
		return "", nil, errors.New("not handled")
	})

	require.NoError(t, jwkbb.RegisterX509Encoder(ident, enc))
	t.Cleanup(func() { jwkbb.UnregisterX509Encoder(ident) })

	// Second registration under the same ident is silent and successful.
	require.NoError(t, jwkbb.RegisterX509Encoder(ident, enc))
}

// Unregister of an unknown ident is silent; no panic.
func TestUnregisterX509Encoder_UnknownIdent(t *testing.T) {
	require.NotPanics(t, func() {
		jwkbb.UnregisterX509Encoder("never-registered")
	})
}

// Unregister of an unknown decoder ident is silent; no panic.
func TestUnregisterX509Decoder_UnknownIdent(t *testing.T) {
	require.NotPanics(t, func() {
		jwkbb.UnregisterX509Decoder("never-registered")
	})
}

// Iterator early-termination (via break) must not leak goroutines or
// leave locks held.
func TestX509Encoders_IteratorEarlyExit(t *testing.T) {
	seen := 0
	for range jwkbb.X509Encoders() {
		seen++
		break
	}
	require.GreaterOrEqual(t, seen, 1, "at least the default encoder should be present")
	// If the mutex were not released, a subsequent Register call would
	// hang indefinitely; require.Eventually would mask that, so we
	// just make a single register call that will deadlock the test if
	// the snapshot iterator holds the lock.
	ident := "iterator-exit-probe"
	require.NoError(t, jwkbb.RegisterX509Encoder(ident, jwkbb.X509EncodeFunc(func(any) (string, []byte, error) {
		return "", nil, errors.New("probe")
	})))
	jwkbb.UnregisterX509Encoder(ident)
}
