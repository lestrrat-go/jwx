package jwkbb_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwk/jwkbb"
	"github.com/stretchr/testify/require"
)

// The default encoder handles stdlib types out of the box.
func TestEncodePEM_DefaultEncoder_Stdlib(t *testing.T) {
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	out, err := jwkbb.EncodePEM(raw)
	require.NoError(t, err, "default encoder should handle *ecdsa.PrivateKey")
	require.NotEmpty(t, out)

	block, _ := pem.Decode(out)
	require.NotNil(t, block)
	require.Equal(t, jwkbb.ECPrivateKeyBlockType, block.Type)
}

// Unsupported raw types surface through the error-join path.
func TestEncodePEM_DefaultEncoder_Unsupported(t *testing.T) {
	_, err := jwkbb.EncodePEM("not a key")
	require.Error(t, err, "default encoder must reject unsupported types")
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
			return "", nil, nil
		}))
		require.Error(t, err)
	})
}

// A registered custom encoder must be tried — its output should round-trip
// through pem.Decode with the block type it produced.
func TestRegisterX509Encoder_CustomTakesEffect(t *testing.T) {
	type fakeKey struct{ tag string }

	const blockType = "FAKE KEY"
	const customBody = "custom-der"
	ident := "test-custom-encoder"

	require.NoError(t, jwkbb.RegisterX509Encoder(ident, jwkbb.X509EncodeFunc(func(v any) (string, []byte, error) {
		fk, ok := v.(*fakeKey)
		if !ok {
			return "", nil, fmt.Errorf("not my type")
		}
		return blockType, []byte(customBody + ":" + fk.tag), nil
	})))
	t.Cleanup(func() { jwkbb.UnregisterX509Encoder(ident) })

	got, err := jwkbb.EncodePEM(&fakeKey{tag: "abc"})
	require.NoError(t, err)

	block, _ := pem.Decode(got)
	require.NotNil(t, block)
	require.Equal(t, blockType, block.Type)
	require.Equal(t, customBody+":abc", string(block.Bytes))
}

// Duplicate-ident Register is a no-op (preserves idempotent init() pattern).
func TestRegisterX509Encoder_DuplicateIdentIsNoop(t *testing.T) {
	ident := "test-duplicate-encoder"
	calls := 0
	enc := jwkbb.X509EncodeFunc(func(_ any) (string, []byte, error) {
		calls++
		return "", nil, errors.New("not handled")
	})

	require.NoError(t, jwkbb.RegisterX509Encoder(ident, enc))
	t.Cleanup(func() { jwkbb.UnregisterX509Encoder(ident) })

	// Second registration under the same ident must be a silent no-op.
	require.NoError(t, jwkbb.RegisterX509Encoder(ident, enc))
}

// Unregister of an unknown ident is silent; no panic, no error return.
func TestUnregisterX509Encoder_UnknownIdent(t *testing.T) {
	require.NotPanics(t, func() {
		jwkbb.UnregisterX509Encoder("never-registered")
	})
}
