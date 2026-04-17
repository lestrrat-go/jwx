package jwkbb_test

import (
	"encoding/pem"
	"errors"
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwk/jwkbb"
	"github.com/stretchr/testify/require"
)

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
