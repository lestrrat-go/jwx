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
	"io"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/internal/ecutil"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/x25519"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func GenerateRsaKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func GenerateRsaJwk() (jwk.Key, error) {
	key, err := GenerateRsaKey()
	if err != nil {
		return nil, errors.Wrap(err, `failed to generate RSA private key`)
	}

	k, err := jwk.New(key)
	if err != nil {
		return nil, errors.Wrap(err, `failed to generate jwk.RSAPrivateKey`)
	}

	return k, nil
}

func GenerateRsaPublicJwk() (jwk.Key, error) {
	key, err := GenerateRsaJwk()
	if err != nil {
		return nil, errors.Wrap(err, `failed to generate jwk.RSAPrivateKey`)
	}

	return jwk.PublicKeyOf(key)
}

func GenerateEcdsaKey(alg jwa.EllipticCurveAlgorithm) (*ecdsa.PrivateKey, error) {
	var crv elliptic.Curve
	if tmp, ok := ecutil.CurveForAlgorithm(alg); ok {
		crv = tmp
	} else {
		return nil, errors.Errorf(`invalid curve algorithm %s`, alg)
	}

	return ecdsa.GenerateKey(crv, rand.Reader)
}

func GenerateEcdsaJwk() (jwk.Key, error) {
	key, err := GenerateEcdsaKey(jwa.P521)
	if err != nil {
		return nil, errors.Wrap(err, `failed to generate ECDSA private key`)
	}

	k, err := jwk.New(key)
	if err != nil {
		return nil, errors.Wrap(err, `failed to generate jwk.ECDSAPrivateKey`)
	}

	return k, nil
}

func GenerateEcdsaPublicJwk() (jwk.Key, error) {
	key, err := GenerateEcdsaJwk()
	if err != nil {
		return nil, errors.Wrap(err, `failed to generate jwk.ECDSAPrivateKey`)
	}

	return jwk.PublicKeyOf(key)
}

func GenerateSymmetricKey() []byte {
	sharedKey := make([]byte, 64)
	rand.Read(sharedKey)
	return sharedKey
}

func GenerateSymmetricJwk() (jwk.Key, error) {
	key, err := jwk.New(GenerateSymmetricKey())
	if err != nil {
		return nil, errors.Wrap(err, `failed to generate jwk.SymmetricKey`)
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
		return nil, errors.Wrap(err, `failed to generate Ed25519 private key`)
	}

	k, err := jwk.New(key)
	if err != nil {
		return nil, errors.Wrap(err, `failed to generate jwk.OKPPrivateKey`)
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
		return nil, errors.Wrap(err, `failed to generate X25519 private key`)
	}

	k, err := jwk.New(key)
	if err != nil {
		return nil, errors.Wrap(err, `failed to generate jwk.OKPPrivateKey`)
	}

	return k, nil
}

func WriteFile(template string, src io.Reader) (string, func(), error) {
	file, cleanup, err := CreateTempFile(template)
	if err != nil {
		return "", nil, errors.Wrap(err, `failed to create temporary file`)
	}

	if _, err := io.Copy(file, src); err != nil {
		defer cleanup()
		return "", nil, errors.Wrap(err, `failed to copy content to temporary file`)
	}

	if err := file.Sync(); err != nil {
		defer cleanup()
		return "", nil, errors.Wrap(err, `failed to sync file`)
	}
	return file.Name(), cleanup, nil
}

func WriteJSONFile(template string, v interface{}) (string, func(), error) {
	var buf bytes.Buffer

	enc := json.NewEncoder(&buf)
	if err := enc.Encode(v); err != nil {
		return "", nil, errors.Wrap(err, `failed to encode object to JSON`)
	}
	return WriteFile(template, &buf)
}

func DumpFile(t *testing.T, file string) {
	buf, err := ioutil.ReadFile(file)
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
	file, err := ioutil.TempFile("", template)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to create temporary file")
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
		return nil, errors.Wrapf(err, `failed to open file %s`, file)
	}
	defer f.Close()

	buf, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, errors.Wrapf(err, `failed to read from key file %s`, file)
	}

	return buf, nil
}

func ParseJwkFile(_ context.Context, file string) (jwk.Key, error) {
	buf, err := ReadFile(file)
	if err != nil {
		return nil, errors.Wrapf(err, `failed to read from key file %s`, file)
	}

	key, err := jwk.ParseKey(buf)
	if err != nil {
		return nil, errors.Wrapf(err, `filed to parse JWK in key file %s`, file)
	}

	return key, nil
}

func DecryptJweFile(ctx context.Context, file string, alg jwa.KeyEncryptionAlgorithm, jwkfile string) ([]byte, error) {
	key, err := ParseJwkFile(ctx, jwkfile)
	if err != nil {
		return nil, errors.Wrapf(err, `failed to parse keyfile %s`, file)
	}

	buf, err := ReadFile(file)
	if err != nil {
		return nil, errors.Wrapf(err, `failed to read from encrypted file %s`, file)
	}

	var rawkey interface{}
	if err := key.Raw(&rawkey); err != nil {
		return nil, errors.Wrap(err, `failed to obtain raw key from JWK`)
	}

	return jwe.Decrypt(buf, alg, rawkey)
}

func EncryptJweFile(ctx context.Context, payload []byte, keyalg jwa.KeyEncryptionAlgorithm, keyfile string, contentalg jwa.ContentEncryptionAlgorithm, compressalg jwa.CompressionAlgorithm) (string, func(), error) {
	key, err := ParseJwkFile(ctx, keyfile)
	if err != nil {
		return "", nil, errors.Wrapf(err, `failed to parse keyfile %s`, keyfile)
	}

	var keyif interface{}

	switch keyalg {
	case jwa.RSA1_5, jwa.RSA_OAEP, jwa.RSA_OAEP_256:
		var rawkey rsa.PrivateKey
		if err := key.Raw(&rawkey); err != nil {
			return "", nil, errors.Wrap(err, `failed to obtain raw key`)
		}
		keyif = rawkey.PublicKey
	case jwa.ECDH_ES, jwa.ECDH_ES_A128KW, jwa.ECDH_ES_A192KW, jwa.ECDH_ES_A256KW:
		var rawkey ecdsa.PrivateKey
		if err := key.Raw(&rawkey); err != nil {
			return "", nil, errors.Wrap(err, `failed to obtain raw key`)
		}
		keyif = rawkey.PublicKey
	default:
		var rawkey []byte
		if err := key.Raw(&rawkey); err != nil {
			return "", nil, errors.Wrap(err, `failed to obtain raw key`)
		}
		keyif = rawkey
	}

	buf, err := jwe.Encrypt(payload, keyalg, keyif, contentalg, compressalg)
	if err != nil {
		return "", nil, errors.Wrap(err, `failed to encrypt payload`)
	}

	return WriteFile("jwx-test-*.jwe", bytes.NewReader(buf))
}

func VerifyJwsFile(ctx context.Context, file string, alg jwa.SignatureAlgorithm, jwkfile string) ([]byte, error) {
	key, err := ParseJwkFile(ctx, jwkfile)
	if err != nil {
		return nil, errors.Wrapf(err, `failed to parse keyfile %s`, file)
	}

	buf, err := ReadFile(file)
	if err != nil {
		return nil, errors.Wrapf(err, `failed to read from encrypted file %s`, file)
	}

	var rawkey, pubkey interface{}
	if err := key.Raw(&rawkey); err != nil {
		return nil, errors.Wrap(err, `failed to obtain raw key from JWK`)
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

	return jws.Verify(buf, alg, pubkey)
}

func SignJwsFile(ctx context.Context, payload []byte, alg jwa.SignatureAlgorithm, keyfile string) (string, func(), error) {
	key, err := ParseJwkFile(ctx, keyfile)
	if err != nil {
		return "", nil, errors.Wrapf(err, `failed to parse keyfile %s`, keyfile)
	}

	buf, err := jws.Sign(payload, alg, key)
	if err != nil {
		return "", nil, errors.Wrap(err, `failed to sign payload`)
	}

	return WriteFile("jwx-test-*.jws", bytes.NewReader(buf))
}
