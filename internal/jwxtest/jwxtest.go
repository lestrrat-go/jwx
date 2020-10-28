package jwxtest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/pdebug"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func DumpFile(t *testing.T, file string) {
	buf, err := ioutil.ReadFile(file)
	if !assert.NoError(t, err, `failed to read file %s for debugging`, file) {
		return
	}

	if strings.HasSuffix(file, ".jwe") {
		if !bytes.ContainsRune(buf, '{') {
			// assume compact serialization
			t.Logf("=== BEGIN %s (raw) ===", file)
			t.Logf("%s", buf)
			t.Logf("=== END   %s (raw) ===", file)

			// cross our fingers our jwe implementation works
			m, err := jwe.Parse(buf)
			if !assert.NoError(t, err, `failed to parse JWE encrypted message`) {
				return
			}

			buf, _ = json.MarshalIndent(m, "", "  ")
		}
	}

	if strings.HasSuffix(file, ".jwk") {
		// Assume JSON
		var m map[string]interface{}
		if !assert.NoError(t, json.Unmarshal(buf, &m), `failed to parse contents as JSON`) {
			return
		}

		buf, _ = json.MarshalIndent(m, "", "  ")
	}

	t.Logf("=== BEGIN %s ===", file)
	t.Logf("%s", buf)
	t.Logf("=== END   %s ===", file)
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

func RawECDSAPrivateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
}

func ECDSAPrivateKey() (jwk.Key, error) {
	key, err := RawECDSAPrivateKey()
	if err != nil {
		return nil, errors.Wrap(err, `failed to generate ECDSA private key`)
	}

	k, err := jwk.New(key)
	if err != nil {
		return nil, errors.Wrap(err, `failed to generate jwk.ECDSAPrivateKey`)
	}

	return k, nil
}

func ECDSAPrivateKeyFile() (string, func(), error) {
	key, err := ECDSAPrivateKey()
	if err != nil {
		return "", nil, errors.Wrap(err, `failed to create ECDSA private key`)
	}

	file, cleanup, err := CreateTempFile("jwx-test-*.jwk")
	if err != nil {
		return "", nil, errors.Wrap(err, `failed to create temporary file`)
	}

	enc := json.NewEncoder(file)
	if err := enc.Encode(key); err != nil {
		return "", nil, errors.Wrap(err, `failed to encode ECDSA private key`)
	}
	//nolint:errcheck
	file.Sync()

	return file.Name(), cleanup, nil
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

	if pdebug.Enabled {
		buf, _ := json.MarshalIndent(key, "", "  ")
		pdebug.Printf("%s", buf)
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

	var rawkey ecdsa.PrivateKey
	if err := key.Raw(&rawkey); err != nil {
		return "", nil, errors.Wrap(err, `failed to obtain raw key`)
	}

	buf, err := jwe.Encrypt(payload, keyalg, rawkey.PublicKey, contentalg, compressalg)
	if err != nil {
		return "", nil, errors.Wrap(err, `failed to encrypt payload`)
	}

	file, cleanup, err := CreateTempFile("jwx-test-*.jwe")
	if err != nil {
		return "", nil, errors.Wrap(err, `failed to create temporary file`)
	}

	//nolint:errcheck
	file.Write(buf)
	//nolint:errcheck
	file.Sync()

	return file.Name(), cleanup, nil
}
