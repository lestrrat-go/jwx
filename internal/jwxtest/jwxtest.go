package jwxtest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v2/internal/ecutil"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/x25519"
	"github.com/stretchr/testify/assert"
)

func GenerateRsaKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func GenerateRsaJwk() (jwk.Key, error) {
	key, err := GenerateRsaKey()
	if err != nil {
		return nil, fmt.Errorf(`failed to generate RSA private key: %w`, err)
	}

	k, err := jwk.FromRaw(key)
	if err != nil {
		return nil, fmt.Errorf(`failed to generate jwk.RSAPrivateKey: %w`, err)
	}

	return k, nil
}

func GenerateRsaPublicJwk() (jwk.Key, error) {
	key, err := GenerateRsaJwk()
	if err != nil {
		return nil, fmt.Errorf(`failed to generate jwk.RSAPrivateKey: %w`, err)
	}

	return jwk.PublicKeyOf(key)
}

func GenerateEcdsaKey(alg jwa.EllipticCurveAlgorithm) (*ecdsa.PrivateKey, error) {
	var crv elliptic.Curve
	if tmp, ok := ecutil.CurveForAlgorithm(alg); ok {
		crv = tmp
	} else {
		return nil, fmt.Errorf(`invalid curve algorithm %s`, alg)
	}

	return ecdsa.GenerateKey(crv, rand.Reader)
}

func GenerateEcdsaJwk() (jwk.Key, error) {
	key, err := GenerateEcdsaKey(jwa.P521)
	if err != nil {
		return nil, fmt.Errorf(`failed to generate ECDSA private key: %w`, err)
	}

	k, err := jwk.FromRaw(key)
	if err != nil {
		return nil, fmt.Errorf(`failed to generate jwk.ECDSAPrivateKey: %w`, err)
	}

	return k, nil
}

func GenerateEcdsaPublicJwk() (jwk.Key, error) {
	key, err := GenerateEcdsaJwk()
	if err != nil {
		return nil, fmt.Errorf(`failed to generate jwk.ECDSAPrivateKey: %w`, err)
	}

	return jwk.PublicKeyOf(key)
}

func GenerateSymmetricKey() []byte {
	sharedKey := make([]byte, 64)
	rand.Read(sharedKey)
	return sharedKey
}

func GenerateSymmetricJwk() (jwk.Key, error) {
	key, err := jwk.FromRaw(GenerateSymmetricKey())
	if err != nil {
		return nil, fmt.Errorf(`failed to generate jwk.SymmetricKey: %w`, err)
	}

	return key, nil
}

func GenerateEd25519Key() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

func GenerateEd25519Jwk() (jwk.Key, error) {
	key, err := GenerateEd25519Key()
	if err != nil {
		return nil, fmt.Errorf(`failed to generate Ed25519 private key: %w`, err)
	}

	k, err := jwk.FromRaw(key)
	if err != nil {
		return nil, fmt.Errorf(`failed to generate jwk.OKPPrivateKey: %w`, err)
	}

	return k, nil
}

func GenerateX25519Key() (x25519.PrivateKey, error) {
	_, priv, err := x25519.GenerateKey(rand.Reader)
	return priv, err
}

func GenerateX25519Jwk() (jwk.Key, error) {
	key, err := GenerateX25519Key()
	if err != nil {
		return nil, fmt.Errorf(`failed to generate X25519 private key: %w`, err)
	}

	k, err := jwk.FromRaw(key)
	if err != nil {
		return nil, fmt.Errorf(`failed to generate jwk.OKPPrivateKey: %w`, err)
	}

	return k, nil
}

func WriteFile(template string, src io.Reader) (string, func(), error) {
	file, cleanup, err := CreateTempFile(template)
	if err != nil {
		return "", nil, fmt.Errorf(`failed to create temporary file: %w`, err)
	}

	if _, err := io.Copy(file, src); err != nil {
		defer cleanup()
		return "", nil, fmt.Errorf(`failed to copy content to temporary file: %w`, err)
	}

	if err := file.Sync(); err != nil {
		defer cleanup()
		return "", nil, fmt.Errorf(`failed to sync file: %w`, err)
	}
	return file.Name(), cleanup, nil
}

func WriteJSONFile(template string, v interface{}) (string, func(), error) {
	var buf bytes.Buffer

	enc := json.NewEncoder(&buf)
	if err := enc.Encode(v); err != nil {
		return "", nil, fmt.Errorf(`failed to encode object to JSON: %w`, err)
	}
	return WriteFile(template, &buf)
}

func DumpFile(t *testing.T, file string) {
	buf, err := os.ReadFile(file)
	if !assert.NoError(t, err, `failed to read file %s for debugging`, file) {
		return
	}

	if isHash, isArray := bytes.ContainsRune(buf, '{'), bytes.ContainsRune(buf, '['); isHash || isArray {
		// Looks like a JSON-like thing. Dump that in a formatted manner, and
		// be done with it

		var v interface{}
		if isHash {
			v = map[string]interface{}{}
		} else {
			v = []interface{}{}
		}

		if !assert.NoError(t, json.Unmarshal(buf, &v), `failed to parse contents as JSON`) {
			return
		}

		buf, _ = json.MarshalIndent(v, "", "  ")
		t.Logf("=== BEGIN %s (formatted JSON) ===", file)
		t.Logf("%s", buf)
		t.Logf("=== END   %s (formatted JSON) ===", file)
		return
	}

	// If the contents do not look like JSON, then we attempt to parse each content
	// based on heuristics (from its file name) and do our best
	t.Logf("=== BEGIN %s (raw) ===", file)
	t.Logf("%s", buf)
	t.Logf("=== END   %s (raw) ===", file)

	if strings.HasSuffix(file, ".jwe") {
		// cross our fingers our jwe implementation works
		m, err := jwe.Parse(buf)
		if !assert.NoError(t, err, `failed to parse JWE encrypted message`) {
			return
		}

		buf, _ = json.MarshalIndent(m, "", "  ")
	}

	t.Logf("=== BEGIN %s (formatted JSON) ===", file)
	t.Logf("%s", buf)
	t.Logf("=== END   %s (formatted JSON) ===", file)
}

func CreateTempFile(template string) (*os.File, func(), error) {
	file, err := os.CreateTemp("", template)
	if err != nil {
		return nil, nil, fmt.Errorf(`failed to create temporary file: %w`, err)
	}

	cleanup := func() {
		file.Close()
		os.Remove(file.Name())
	}

	return file, cleanup, nil
}

func ReadFile(file string) ([]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf(`failed to open file %s: %w`, file, err)
	}
	defer f.Close()

	buf, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf(`failed to read from key file %s: %w`, file, err)
	}

	return buf, nil
}

func ParseJwkFile(_ context.Context, file string) (jwk.Key, error) {
	buf, err := ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf(`failed to read from key file %s: %w`, file, err)
	}

	key, err := jwk.ParseKey(buf)
	if err != nil {
		return nil, fmt.Errorf(`filed to parse JWK in key file %s: %w`, file, err)
	}

	return key, nil
}

func DecryptJweFile(ctx context.Context, file string, alg jwa.KeyEncryptionAlgorithm, jwkfile string) ([]byte, error) {
	key, err := ParseJwkFile(ctx, jwkfile)
	if err != nil {
		return nil, fmt.Errorf(`failed to parse keyfile %s: %w`, file, err)
	}

	buf, err := ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf(`failed to read from encrypted file %s: %w`, file, err)
	}

	var rawkey interface{}
	if err := key.Raw(&rawkey); err != nil {
		return nil, fmt.Errorf(`failed to obtain raw key from JWK: %w`, err)
	}

	return jwe.Decrypt(buf, jwe.WithKey(alg, rawkey))
}

func EncryptJweFile(ctx context.Context, payload []byte, keyalg jwa.KeyEncryptionAlgorithm, keyfile string, contentalg jwa.ContentEncryptionAlgorithm, compressalg jwa.CompressionAlgorithm) (string, func(), error) {
	key, err := ParseJwkFile(ctx, keyfile)
	if err != nil {
		return "", nil, fmt.Errorf(`failed to parse keyfile %s: %w`, keyfile, err)
	}

	var keyif interface{}

	switch keyalg {
	case jwa.RSA1_5, jwa.RSA_OAEP, jwa.RSA_OAEP_256:
		var rawkey rsa.PrivateKey
		if err := key.Raw(&rawkey); err != nil {
			return "", nil, fmt.Errorf(`failed to obtain raw key: %w`, err)
		}
		keyif = rawkey.PublicKey
	case jwa.ECDH_ES, jwa.ECDH_ES_A128KW, jwa.ECDH_ES_A192KW, jwa.ECDH_ES_A256KW:
		var rawkey ecdsa.PrivateKey
		if err := key.Raw(&rawkey); err != nil {
			return "", nil, fmt.Errorf(`failed to obtain raw key: %w`, err)
		}
		keyif = rawkey.PublicKey
	default:
		var rawkey []byte
		if err := key.Raw(&rawkey); err != nil {
			return "", nil, fmt.Errorf(`failed to obtain raw key: %w`, err)
		}
		keyif = rawkey
	}

	buf, err := jwe.Encrypt(payload, jwe.WithKey(keyalg, keyif), jwe.WithContentEncryption(contentalg), jwe.WithCompress(compressalg))
	if err != nil {
		return "", nil, fmt.Errorf(`failed to encrypt payload: %w`, err)
	}

	return WriteFile("jwx-test-*.jwe", bytes.NewReader(buf))
}

func VerifyJwsFile(ctx context.Context, file string, alg jwa.SignatureAlgorithm, jwkfile string) ([]byte, error) {
	key, err := ParseJwkFile(ctx, jwkfile)
	if err != nil {
		return nil, fmt.Errorf(`failed to parse keyfile %s: %w`, file, err)
	}

	buf, err := ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf(`failed to read from encrypted file %s: %w`, file, err)
	}

	var rawkey, pubkey interface{}
	if err := key.Raw(&rawkey); err != nil {
		return nil, fmt.Errorf(`failed to obtain raw key from JWK: %w`, err)
	}
	pubkey = rawkey
	switch tkey := rawkey.(type) {
	case *ecdsa.PrivateKey:
		pubkey = tkey.PublicKey
	case *rsa.PrivateKey:
		pubkey = tkey.PublicKey
	case *ed25519.PrivateKey:
		pubkey = tkey.Public()
	}

	return jws.Verify(buf, jws.WithKey(alg, pubkey))
}

func SignJwsFile(ctx context.Context, payload []byte, alg jwa.SignatureAlgorithm, keyfile string) (string, func(), error) {
	key, err := ParseJwkFile(ctx, keyfile)
	if err != nil {
		return "", nil, fmt.Errorf(`failed to parse keyfile %s: %w`, keyfile, err)
	}

	buf, err := jws.Sign(payload, jws.WithKey(alg, key))
	if err != nil {
		return "", nil, fmt.Errorf(`failed to sign payload: %w`, err)
	}

	return WriteFile("jwx-test-*.jws", bytes.NewReader(buf))
}
