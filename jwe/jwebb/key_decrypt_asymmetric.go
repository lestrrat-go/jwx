package jwebb

import (
	"crypto"
	"crypto/aes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"

	"github.com/lestrrat-go/jwx/v3/internal/keyconv"
	"github.com/lestrrat-go/jwx/v3/jwe/internal/concatkdf"
	"github.com/lestrrat-go/jwx/v3/jwe/internal/keyenc"
	"github.com/lestrrat-go/jwx/v3/jwe/internal/keygen"
)

const (
	KeySize16 = 16
	KeySize24 = 24
	KeySize32 = 32
)

const (
	ECDH_ES        = "ECDH-ES"
	ECDH_ES_A128KW = "ECDH-ES+A128KW"
	ECDH_ES_A192KW = "ECDH-ES+A192KW"
	ECDH_ES_A256KW = "ECDH-ES+A256KW"
)

func KeyEncryptionIsECDHES(alg string) bool {
	switch alg {
	case ECDH_ES, ECDH_ES_A128KW, ECDH_ES_A192KW, ECDH_ES_A256KW:
		return true
	default:
		return false
	}
}

func contentEncryptionKeySize(ctalg string) (uint32, error) {
	switch ctalg {
	case "A128GCM":
		return 16, nil
	case "A192GCM":
		return 24, nil
	case "A256GCM":
		return 32, nil
	case "A128CBC-HS256":
		return 32, nil
	case "A192CBC-HS384":
		return 48, nil
	case "A256CBC-HS512":
		return 64, nil
	default:
		return 0, fmt.Errorf(`unsupported content encryption algorithm %s`, ctalg)
	}
}

func KeyEncryptionECDHESKeySize(alg, ctalg string) (string, uint32, bool, error) {
	switch alg {
	case ECDH_ES:
		keysize, err := contentEncryptionKeySize(ctalg)
		if err != nil {
			return "", 0, false, err
		}
		return ctalg, keysize, false, nil
	case ECDH_ES_A128KW:
		return alg, KeySize16, true, nil
	case ECDH_ES_A192KW:
		return alg, KeySize24, true, nil
	case ECDH_ES_A256KW:
		return alg, KeySize32, true, nil
	default:
		return "", 0, false, fmt.Errorf(`unsupported key encryption algorithm %s`, alg)
	}
}

func DeriveECDHES(alg string, apu, apv []byte, privkeyif, pubkeyif any, keysize uint32) ([]byte, error) {
	pubinfo := make([]byte, 4)
	binary.BigEndian.PutUint32(pubinfo, keysize*8)

	var privkey *ecdh.PrivateKey
	var pubkey *ecdh.PublicKey
	if err := keyconv.ECDHPrivateKey(&privkey, privkeyif); err != nil {
		return nil, fmt.Errorf(`keyenc.DeriveECDHES: %w`, err)
	}
	if err := keyconv.ECDHPublicKey(&pubkey, pubkeyif); err != nil {
		return nil, fmt.Errorf(`keyenc.DeriveECDHES: %w`, err)
	}

	zBytes, err := privkey.ECDH(pubkey)
	if err != nil {
		return nil, fmt.Errorf(`keyenc.DeriveECDHES: unable to determine Z: %w`, err)
	}
	kdf := concatkdf.New(crypto.SHA256, []byte(alg), zBytes, apu, apv, pubinfo, []byte{})
	key := make([]byte, keysize)
	if _, err := kdf.Read(key); err != nil {
		return nil, fmt.Errorf(`keyenc.DeriveECDHES: failed to read kdf: %w`, err)
	}

	return key, nil
}

func KeyDecryptECDHESKeyWrap(recipientKey, enckey []byte, alg string, apu, apv []byte, privkey, pubkey any, keysize uint32) ([]byte, error) {
	key, err := DeriveECDHES(alg, apu, apv, privkey, pubkey, keysize)
	if err != nil {
		return nil, fmt.Errorf(`failed to derive ECDHES encryption key: %w`, err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf(`failed to create cipher for ECDH-ES key wrap: %w`, err)
	}

	return keyenc.Unwrap(block, enckey)
}

func KeyDecryptECDHES(recipientKey, enckey []byte, alg string, apu, apv []byte, privkey, pubkey any, keysize uint32) ([]byte, error) {
	key, err := DeriveECDHES(alg, apu, apv, privkey, pubkey, keysize)
	if err != nil {
		return nil, fmt.Errorf(`failed to derive ECDHES encryption key: %w`, err)
	}
	return key, nil
}

// RSA key decryption functions

const (
	RSA1_5       = "RSA1_5"
	RSA_OAEP     = "RSA-OAEP"
	RSA_OAEP_256 = "RSA-OAEP-256"
	RSA_OAEP_384 = "RSA-OAEP-384"
	RSA_OAEP_512 = "RSA-OAEP-512"
)

func KeyEncryptionIsRSA15(alg string) bool {
	return alg == RSA1_5
}

func KeyEncryptionIsRSAOAEP(alg string) bool {
	switch alg {
	case RSA_OAEP, RSA_OAEP_256, RSA_OAEP_384, RSA_OAEP_512:
		return true
	default:
		return false
	}
}

func KeyDecryptRSA15(recipientKey, enckey []byte, privkeyif any, keysize int) ([]byte, error) {
	var privkey *rsa.PrivateKey
	if err := keyconv.RSAPrivateKey(&privkey, privkeyif); err != nil {
		return nil, fmt.Errorf(`keyenc.KeyDecryptRSA15: %w`, err)
	}

	// Perform some input validation.
	expectedlen := privkey.PublicKey.N.BitLen() / 8
	if expectedlen != len(enckey) {
		// Input size is incorrect, the encrypted payload should always match
		// the size of the public modulus (e.g. using a 2048 bit key will
		// produce 256 bytes of output). Reject this since it's invalid input.
		return nil, fmt.Errorf(
			"input size for key decrypt is incorrect (expected %d, got %d)",
			expectedlen,
			len(enckey),
		)
	}

	// Generate a random CEK of the required size
	generator := keygen.NewRandom(keysize * 2)
	bk, err := generator.Generate()
	if err != nil {
		return nil, fmt.Errorf(`failed to generate key`)
	}
	cek := bk.Bytes()

	// Use a defer/recover pattern to handle potential panics from DecryptPKCS1v15SessionKey
	defer func() {
		// DecryptPKCS1v15SessionKey sometimes panics on an invalid payload
		// because of an index out of bounds error, which we want to ignore.
		// This has been fixed in Go 1.3.1 (released 2014/08/13), the recover()
		// only exists for preventing crashes with unpatched versions.
		// See: https://groups.google.com/forum/#!topic/golang-dev/7ihX6Y6kx9k
		// See: https://code.google.com/p/go/source/detail?r=58ee390ff31602edb66af41ed10901ec95904d33
		_ = recover()
	}()

	// When decrypting an RSA-PKCS1v1.5 payload, we must take precautions to
	// prevent chosen-ciphertext attacks as described in RFC 3218, "Preventing
	// the Million Message Attack on Cryptographic Message Syntax". We are
	// therefore deliberately ignoring errors here.
	_ = rsa.DecryptPKCS1v15SessionKey(rand.Reader, privkey, enckey, cek)

	return cek, nil
}

func KeyDecryptRSAOAEP(recipientKey, enckey []byte, alg string, privkeyif any) ([]byte, error) {
	var privkey *rsa.PrivateKey
	if err := keyconv.RSAPrivateKey(&privkey, privkeyif); err != nil {
		return nil, fmt.Errorf(`keyenc.KeyDecryptRSAOAEP: %w`, err)
	}

	var hash hash.Hash
	switch alg {
	case RSA_OAEP:
		hash = sha1.New()
	case RSA_OAEP_256:
		hash = sha256.New()
	case RSA_OAEP_384:
		hash = sha512.New384()
	case RSA_OAEP_512:
		hash = sha512.New()
	default:
		return nil, fmt.Errorf(`failed to generate key encrypter for RSA-OAEP: RSA_OAEP/RSA_OAEP_256/RSA_OAEP_384/RSA_OAEP_512 required`)
	}

	return rsa.DecryptOAEP(hash, rand.Reader, privkey, enckey, []byte{})
}
