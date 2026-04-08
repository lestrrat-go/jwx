package jwebb

import (
	"crypto"
	"crypto/aes"
	"encoding/binary"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/internal/tokens"
	"github.com/lestrrat-go/jwx/v4/jwe/internal/concatkdf"
	"github.com/lestrrat-go/jwx/v4/jwe/internal/keygen"
)

// ECDHESKeyGenerator is implemented by raw public key types that can
// perform ECDH-ES key generation for JWE encryption. This allows
// external modules to provide ECDH-ES support for key types not in
// Go's standard library (e.g., X448 from cloudflare/circl).
//
// When jwe.Encrypt encounters a raw key implementing this interface
// in the ECDH-ES path, it delegates key generation to the key itself.
type ECDHESKeyGenerator interface {
	// GenerateECDHES generates an ephemeral key pair, performs the ECDH
	// operation with this public key, and derives the key encryption key
	// via Concat KDF.
	//
	// alg is the derived algorithm label used in the KDF (the content
	// encryption algorithm for bare ECDH-ES, or the key wrapping
	// algorithm for ECDH-ES+AxxxKW).
	//
	// Returns the derived key bytes and the ephemeral public key. The
	// ephemeral public key must be importable by jwk.Import so it can
	// be stored as the 'epk' JWE header.
	GenerateECDHES(alg string, keysize int, apu, apv []byte) (derivedKey []byte, ephemeralPubKey any, err error)
}

// ECDHESKeyDeriver is implemented by raw private key types that can
// perform ECDH-ES key derivation for JWE decryption. This allows
// external modules to provide ECDH-ES support for key types not in
// Go's standard library (e.g., X448 from cloudflare/circl).
//
// When jwe.Decrypt encounters a raw key implementing this interface
// in the ECDH-ES path, it delegates key derivation to the key itself.
type ECDHESKeyDeriver interface {
	// DeriveECDHES performs the ECDH operation using this private key and
	// the given ephemeral public key, then derives the key via Concat KDF.
	//
	// The ephemeralPubKey is the raw key exported from the 'epk' JWE header.
	DeriveECDHES(alg string, keysize int, ephemeralPubKey any, apu, apv []byte) ([]byte, error)
}

// DeriveECDHESRaw performs the Concat KDF key derivation used in ECDH-ES,
// given a pre-computed ECDH shared secret (Z). This is a low-level helper
// for ECDHESKeyGenerator/ECDHESKeyDeriver implementations that handle the
// ECDH computation themselves.
func DeriveECDHESRaw(alg string, zBytes, apu, apv []byte, keysize int) ([]byte, error) {
	pubinfo := make([]byte, 4)
	binary.BigEndian.PutUint32(pubinfo, uint32(keysize)*tokens.BitsPerByte)
	kdf := concatkdf.New(crypto.SHA256, []byte(alg), zBytes, apu, apv, pubinfo, []byte{})
	key := make([]byte, keysize)
	if _, err := kdf.Read(key); err != nil {
		return nil, fmt.Errorf(`jwebb.DeriveECDHESRaw: failed to read kdf: %w`, err)
	}
	return key, nil
}

// KeyEncryptECDHESCustom encrypts using ECDH-ES with a custom key type
// that implements ECDHESKeyGenerator.
func KeyEncryptECDHESCustom(cek []byte, alg string, apu, apv []byte, gen ECDHESKeyGenerator, keysize uint32, ctalg string, keywrap bool) (keygen.ByteSource, error) {
	var derivedAlg string
	if alg == tokens.ECDH_ES {
		derivedAlg = ctalg
	} else {
		derivedAlg = alg
	}

	derivedKey, epk, err := gen.GenerateECDHES(derivedAlg, int(keysize), apu, apv)
	if err != nil {
		return nil, fmt.Errorf(`failed to generate ECDH-ES key: %w`, err)
	}

	bwpk := keygen.ByteWithECPublicKey{
		PublicKey: epk,
		ByteKey:   keygen.ByteKey(derivedKey),
	}

	if !keywrap {
		return bwpk, nil
	}

	block, err := aes.NewCipher(bwpk.Bytes())
	if err != nil {
		return nil, fmt.Errorf(`failed to generate cipher from generated key: %w`, err)
	}

	jek, err := Wrap(block, cek)
	if err != nil {
		return nil, fmt.Errorf(`failed to wrap data: %w`, err)
	}

	bwpk.ByteKey = keygen.ByteKey(jek)
	return bwpk, nil
}

// KeyDecryptECDHESCustom decrypts using ECDH-ES with a custom key type
// that implements ECDHESKeyDeriver.
func KeyDecryptECDHESCustom(recipientKey []byte, alg string, apu, apv []byte, deriver ECDHESKeyDeriver, pubkey any, keysize uint32, keywrap bool) ([]byte, error) {
	derivedKey, err := deriver.DeriveECDHES(alg, int(keysize), pubkey, apu, apv)
	if err != nil {
		return nil, fmt.Errorf(`failed to derive ECDH-ES key: %w`, err)
	}

	if !keywrap {
		return derivedKey, nil
	}

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf(`failed to create cipher for ECDH-ES key unwrap: %w`, err)
	}

	return Unwrap(block, recipientKey)
}
