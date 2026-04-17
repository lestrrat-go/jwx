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
		err := jwk.RegisterKeyImporter(func(invalidImportRaw) (jwk.Key, error) {
			return makeInvalidECDSAJWK()
		})
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

func TestImportRejectsInvalidKeyFromCustomImporter(t *testing.T) {
	registerInvalidImporter(t)

	_, err := jwk.Import[jwk.Key](invalidImportRaw{})
	require.Error(t, err)
	require.ErrorIs(t, err, jwk.ImportError())
	require.True(t, jwk.IsKeyValidationError(err), `Import should preserve key-validation identity`)
}

func TestParseKeyWithX509DecoderRejectsInvalidImportedKey(t *testing.T) {
	ident := "test-invalid-x509-import-boundary"
	err := jwkbb.RegisterX509Decoder(ident, jwkbb.X509DecodeFunc(func(block *pem.Block) (any, error) {
		if block.Type != "INVALID ECDSA" {
			return nil, fmt.Errorf("unsupported type")
		}
		return invalidImportRaw{}, nil
	}))
	require.NoError(t, err)
	t.Cleanup(func() {
		jwkbb.UnregisterX509Decoder(ident)
	})

	src := []byte(`-----BEGIN INVALID ECDSA-----
ZHVtbXk=
-----END INVALID ECDSA-----`)
	_, err = jwk.ParseKey(src, jwk.WithX509(true))
	require.Error(t, err)
	require.True(t, jwk.IsKeyValidationError(err), `ParseKey should preserve key-validation identity`)
}

func TestParseKeyRejectsInvalidKeyFromCustomParser(t *testing.T) {
	registerInvalidParser(t)

	_, err := jwk.ParseKey([]byte(`{"kty":"EC","force-invalid-parser":true}`))
	require.Error(t, err)
	require.True(t, jwk.IsKeyValidationError(err), `ParseKey should validate keys returned from custom parsers`)
}
