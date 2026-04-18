package jwkbb_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
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

func TestRegisterX509Decoder_NilDecoder(t *testing.T) {
	require.NotPanics(t, func() {
		err := jwkbb.RegisterX509Decoder[any]("TEST NIL DECODER", nil)
		require.Error(t, err)
	})
}

func TestRegisterX509Decoder_EmptyBlockType(t *testing.T) {
	require.NotPanics(t, func() {
		err := jwkbb.RegisterX509Decoder[any]("", jwkbb.X509DecodeFunc[any](func(*pem.Block) (any, error) {
			return nil, errors.New("unused")
		}))
		require.Error(t, err)
	})
}

// Unregistering an unknown block type is silent; no panic.
func TestUnregisterX509Decoder_UnknownBlockType(t *testing.T) {
	require.NotPanics(t, func() {
		jwkbb.UnregisterX509Decoder("NEVER REGISTERED")
	})
}

// A registered custom decoder owns its block type and is reachable
// via DecodeX509, which dispatches by block.Type.
func TestRegisterX509Decoder_CustomReachable(t *testing.T) {
	const blockType = "CUSTOM TEST BLOCK"
	type customPayload struct{ tag string }

	require.NoError(t, jwkbb.RegisterX509Decoder[*customPayload](blockType, jwkbb.X509DecodeFunc[*customPayload](func(b *pem.Block) (*customPayload, error) {
		return &customPayload{tag: string(b.Bytes)}, nil
	})))
	t.Cleanup(func() { jwkbb.UnregisterX509Decoder(blockType) })

	got, err := jwkbb.DecodeX509(&pem.Block{Type: blockType, Bytes: []byte("abc")})
	require.NoError(t, err)
	require.IsType(t, &customPayload{}, got, "decoder should produce its declared return type")
	require.Equal(t, "abc", got.(*customPayload).tag)
}

// Re-registering the same block type overwrites the previous
// decoder. Direct string→decoder dispatch, "last registration wins."
func TestRegisterX509Decoder_OverwritesSameBlockType(t *testing.T) {
	const blockType = "CUSTOM OVERWRITE BLOCK"

	require.NoError(t, jwkbb.RegisterX509Decoder[string](blockType, jwkbb.X509DecodeFunc[string](func(*pem.Block) (string, error) {
		return "first", nil
	})))
	t.Cleanup(func() { jwkbb.UnregisterX509Decoder(blockType) })

	require.NoError(t, jwkbb.RegisterX509Decoder[string](blockType, jwkbb.X509DecodeFunc[string](func(*pem.Block) (string, error) {
		return "second", nil
	})))

	got, err := jwkbb.DecodeX509(&pem.Block{Type: blockType})
	require.NoError(t, err)
	require.Equal(t, "second", got, "the later registration should own the block type")
}

// DecodeX509 with no matching registration surfaces a clear error
// rather than silently returning zero values.
func TestDecodeX509_UnknownBlockType(t *testing.T) {
	_, err := jwkbb.DecodeX509(&pem.Block{Type: "NEVER REGISTERED BLOCK"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "NEVER REGISTERED BLOCK")
}

// fakeKey is declared at package scope so its type identity is stable
// across the encoder-registry tests that key off it.
type fakeKey struct{ tag string }

func fakeKeyEncoder(v *fakeKey) (string, []byte, error) {
	return "FAKE KEY", []byte("custom-der:" + v.tag), nil
}

func TestRegisterX509Encoder_NilError(t *testing.T) {
	require.NotPanics(t, func() {
		err := jwkbb.RegisterX509Encoder[*fakeKey](nil)
		require.Error(t, err)
	})
}

// A registered custom encoder must be reachable via EncodePEM, which
// dispatches by the runtime type of its input.
func TestRegisterX509Encoder_CustomReachable(t *testing.T) {
	require.NoError(t, jwkbb.RegisterX509Encoder[*fakeKey](jwkbb.X509EncodeFunc[*fakeKey](fakeKeyEncoder)))
	t.Cleanup(func() { jwkbb.UnregisterX509Encoder[*fakeKey]() })

	out, err := jwkbb.EncodePEM(&fakeKey{tag: "abc"})
	require.NoError(t, err)

	block, rest := pem.Decode(out)
	require.NotNil(t, block, "EncodePEM should emit a decodable PEM block")
	require.Equal(t, "FAKE KEY", block.Type, "custom encoder should own its type")
	require.Equal(t, "custom-der:abc", string(block.Bytes))
	require.Empty(t, rest, "no trailing bytes expected")
}

// Re-registering the same T overwrites the previous encoder. The
// registry is a direct type→encoder dispatch, so "last registration
// wins" is the intended semantic for both tests that swap in a
// temporary encoder and extension modules that want to replace a
// stdlib default.
func TestRegisterX509Encoder_OverwritesSameType(t *testing.T) {
	require.NoError(t, jwkbb.RegisterX509Encoder[*fakeKey](jwkbb.X509EncodeFunc[*fakeKey](func(*fakeKey) (string, []byte, error) {
		return "", nil, errors.New("first encoder")
	})))
	t.Cleanup(func() { jwkbb.UnregisterX509Encoder[*fakeKey]() })

	require.NoError(t, jwkbb.RegisterX509Encoder[*fakeKey](jwkbb.X509EncodeFunc[*fakeKey](fakeKeyEncoder)))

	out, err := jwkbb.EncodePEM(&fakeKey{tag: "winner"})
	require.NoError(t, err, "the second registration should own *fakeKey")

	block, _ := pem.Decode(out)
	require.NotNil(t, block)
	require.Equal(t, "custom-der:winner", string(block.Bytes))
}

// Unregistering a type with no registered encoder is a silent no-op.
func TestUnregisterX509Encoder_NoneRegistered(t *testing.T) {
	type neverRegistered struct{}
	require.NotPanics(t, func() {
		jwkbb.UnregisterX509Encoder[neverRegistered]()
	})
}
