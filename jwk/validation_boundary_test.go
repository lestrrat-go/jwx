package jwk_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"sync"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwk/jwkbb"
	"github.com/stretchr/testify/require"
)

type invalidImportRaw struct{}

type invalidReturningParser struct{}

func (invalidReturningParser) ParseKey(_ *jwk.KeyProbe, _ jwk.KeyUnmarshaler, payload []byte) (jwk.Key, error) {
	if !bytes.Contains(payload, []byte(`"force-invalid-parser":true`)) {
		return nil, jwk.ContinueError()
	}
	return makeInvalidECDSAJWK()
}

var registerInvalidImporterOnce sync.Once
var registerInvalidParserOnce sync.Once
var registerNilNilParserOnce sync.Once

type nilNilReturningParser struct{}

func (nilNilReturningParser) ParseKey(_ *jwk.KeyProbe, _ jwk.KeyUnmarshaler, payload []byte) (jwk.Key, error) {
	if !bytes.Contains(payload, []byte(`"force-nil-parser":true`)) {
		return nil, jwk.ContinueError()
	}
	// Intentional bug pattern under test: a buggy parser may return
	// (nil, nil); jwk.ParseKey must treat it as ContinueError, not as
	// a successful nil-Key result that gets handed back to the caller.
	//nolint:nilnil
	return nil, nil
}

func registerNilNilParser(t *testing.T) {
	t.Helper()
	registerNilNilParserOnce.Do(func() {
		err := jwk.RegisterKeyParser(nilNilReturningParser{})
		require.NoError(t, err)
	})
}

func makeInvalidECDSAJWK() (jwk.Key, error) {
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	key, err := jwk.Import[jwk.ECDSAPublicKey](&raw.PublicKey)
	if err != nil {
		return nil, err
	}
	x, ok := key.X()
	if !ok || len(x) < 2 {
		return nil, fmt.Errorf("missing valid ECDSA X coordinate")
	}
	if err := key.Set(jwk.ECDSAXKey, x[:len(x)/2]); err != nil {
		return nil, err
	}
	return key, nil
}

func registerInvalidImporter(t *testing.T) {
	t.Helper()
	registerInvalidImporterOnce.Do(func() {
		err := jwk.RegisterKeyImporter(
			jwk.KeyImportFunc[invalidImportRaw](func(invalidImportRaw) (jwk.Key, error) {
				return makeInvalidECDSAJWK()
			}),
		)
		require.NoError(t, err)
	})
}

func registerInvalidParser(t *testing.T) {
	t.Helper()
	registerInvalidParserOnce.Do(func() {
		err := jwk.RegisterKeyParser(invalidReturningParser{})
		require.NoError(t, err)
	})
}

// Both the direct Import path and the ParseKey-with-X509 path funnel
// raw keys through the same importer registry, so an invalid key
// produced by a custom importer must be rejected the same way no
// matter which path reached it. The x509 subtest depends on the
// custom importer registered by registerInvalidImporter — running it
// as a sibling top-level test made the outcome depend on Go's test
// ordering, which is why they live together here.
func TestRejectsInvalidKeyFromCustomImporter(t *testing.T) {
	registerInvalidImporter(t)

	t.Run("direct Import", func(t *testing.T) {
		_, err := jwk.Import[jwk.Key](invalidImportRaw{})
		require.Error(t, err)
		require.ErrorIs(t, err, jwk.ImportError())
		require.True(t, jwk.IsKeyValidationError(err), `Import should preserve key-validation identity`)
	})

	t.Run("ParseKey via X509 decoder", func(t *testing.T) {
		const blockType = "INVALID ECDSA"
		err := jwkbb.RegisterX509Decoder[invalidImportRaw](blockType, jwkbb.X509DecodeFunc[invalidImportRaw](func(*pem.Block) (invalidImportRaw, error) {
			return invalidImportRaw{}, nil
		}))
		require.NoError(t, err)
		t.Cleanup(func() {
			jwkbb.UnregisterX509Decoder(blockType)
		})

		src := []byte(`-----BEGIN INVALID ECDSA-----
ZHVtbXk=
-----END INVALID ECDSA-----`)
		_, err = jwk.ParseKey(src, jwk.WithX509(true))
		require.Error(t, err)
		require.True(t, jwk.IsKeyValidationError(err), `ParseKey should preserve key-validation identity`)
	})
}

func TestParseKeyRejectsInvalidKeyFromCustomParser(t *testing.T) {
	registerInvalidParser(t)

	_, err := jwk.ParseKey([]byte(`{"kty":"EC","force-invalid-parser":true}`))
	require.Error(t, err)
	require.True(t, jwk.IsKeyValidationError(err), `ParseKey should validate keys returned from custom parsers`)
}

// A buggy KeyParser returning (nil, nil) must not be treated as a
// successful parse: the caller would receive a nil jwk.Key with nil
// error and panic on the next method call. The dispatch should treat
// (nil, nil) the same as ContinueError and fall through to the next
// registered parser.
func TestParseKeyContinuesPastNilNilCustomParser(t *testing.T) {
	registerNilNilParser(t)

	key, err := jwk.ParseKey([]byte(`{"kty":"oct","k":"AAAA","force-nil-parser":true}`))
	require.NoError(t, err, `ParseKey should fall through to the default parser, not return (nil, nil)`)
	require.NotNil(t, key, `ParseKey must not return a nil Key`)
}
