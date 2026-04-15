package jwebb

import (
	"crypto"
	"crypto/aes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/internal/keyconv"
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

// NewECDHESKeyGenerator normalizes a raw key into an ECDHESKeyGenerator.
// If the key already implements ECDHESKeyGenerator, it is returned as-is.
// Otherwise, stdlib key types (*ecdh.PublicKey, *ecdsa.PublicKey, and their
// private key counterparts) are wrapped in an adapter.
func NewECDHESKeyGenerator(key any) (ECDHESKeyGenerator, error) {
	if gen, ok := key.(ECDHESKeyGenerator); ok {
		return gen, nil
	}

	switch k := key.(type) {
	case *ecdh.PublicKey:
		return &ecdhGenerator{key: k}, nil
	case *ecdh.PrivateKey:
		return &ecdhGenerator{key: k.PublicKey()}, nil
	case ecdh.PrivateKey:
		return &ecdhGenerator{key: k.PublicKey()}, nil
	case *ecdsa.PublicKey:
		return ecdhGeneratorFromECDSAPublic(k)
	case ecdsa.PublicKey:
		return ecdhGeneratorFromECDSAPublic(&k)
	case *ecdsa.PrivateKey:
		return ecdhGeneratorFromECDSAPublic(&k.PublicKey)
	case ecdsa.PrivateKey:
		return ecdhGeneratorFromECDSAPublic(&k.PublicKey)
	default:
		return nil, fmt.Errorf(`unsupported key type for ECDH-ES key generation: %T`, key)
	}
}

// ecdhGeneratorFromECDSAPublic converts an *ecdsa.PublicKey into an
// *ecdh.PublicKey via stdlib (*ecdsa.PublicKey).ECDH() and wraps it in
// ecdhGenerator. This routes every ecdsa-input ECDH-ES path through
// crypto/ecdh, which uses identity matching on named NIST curves and
// refuses anything else — including the generic elliptic.CurveParams
// big-int path. That closes the invalid-curve attack surface that a
// caller-controlled ecdsa.PublicKey.Curve field would otherwise expose
// via the deprecated crypto/elliptic.Curve.ScalarMult.
func ecdhGeneratorFromECDSAPublic(pub *ecdsa.PublicKey) (ECDHESKeyGenerator, error) {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil, fmt.Errorf(`invalid ecdsa public key: nil X or Y`)
	}
	ecdhPub, err := pub.ECDH()
	if err != nil {
		return nil, fmt.Errorf(`failed to convert ecdsa public key to *ecdh.PublicKey: %w`, err)
	}
	return &ecdhGenerator{key: ecdhPub}, nil
}

// NewECDHESKeyDeriver normalizes a raw key into an ECDHESKeyDeriver.
// If the key already implements ECDHESKeyDeriver, it is returned as-is.
// Otherwise, stdlib private key types (*ecdh.PrivateKey, *ecdsa.PrivateKey)
// are wrapped in an adapter.
func NewECDHESKeyDeriver(key any) (ECDHESKeyDeriver, error) {
	if d, ok := key.(ECDHESKeyDeriver); ok {
		return d, nil
	}

	switch k := key.(type) {
	case *ecdh.PrivateKey:
		return &ecdhDeriver{key: k}, nil
	case *ecdsa.PrivateKey:
		return &ecdsaDeriver{key: k}, nil
	default:
		return nil, fmt.Errorf(`unsupported key type for ECDH-ES key derivation: %T`, key)
	}
}

// ecdhGenerator wraps *ecdh.PublicKey to implement ECDHESKeyGenerator.
// Handles both NIST curves (P-256, P-384, P-521) and X25519.
type ecdhGenerator struct {
	key *ecdh.PublicKey
}

func (g *ecdhGenerator) GenerateECDHES(alg string, keysize int, apu, apv []byte) ([]byte, any, error) {
	priv, err := g.key.Curve().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf(`failed to generate ephemeral key: %w`, err)
	}

	z, err := priv.ECDH(g.key)
	if err != nil {
		return nil, nil, fmt.Errorf(`failed to compute ECDH: %w`, err)
	}

	derived, err := DeriveECDHESRaw(alg, z, apu, apv, keysize)
	if err != nil {
		return nil, nil, err
	}

	return derived, priv.PublicKey(), nil
}

// ecdhDeriver wraps *ecdh.PrivateKey to implement ECDHESKeyDeriver.
type ecdhDeriver struct {
	key *ecdh.PrivateKey
}

func (d *ecdhDeriver) DeriveECDHES(alg string, keysize int, ephemeralPubKey any, apu, apv []byte) ([]byte, error) {
	pub, err := keyconv.ECDHPublicKey(ephemeralPubKey)
	if err != nil {
		return nil, fmt.Errorf(`failed to convert ephemeral public key: %w`, err)
	}

	z, err := d.key.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf(`failed to compute ECDH: %w`, err)
	}

	return DeriveECDHESRaw(alg, z, apu, apv, keysize)
}

// ecdsaDeriver wraps *ecdsa.PrivateKey to implement ECDHESKeyDeriver.
type ecdsaDeriver struct {
	key *ecdsa.PrivateKey
}

func (d *ecdsaDeriver) DeriveECDHES(alg string, keysize int, ephemeralPubKey any, apu, apv []byte) ([]byte, error) {
	ecdhPriv, err := d.key.ECDH()
	if err != nil {
		return nil, fmt.Errorf(`failed to convert ECDSA to ECDH private key: %w`, err)
	}

	pub, err := keyconv.ECDHPublicKey(ephemeralPubKey)
	if err != nil {
		return nil, fmt.Errorf(`failed to convert ephemeral public key: %w`, err)
	}

	z, err := ecdhPriv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf(`failed to compute ECDH: %w`, err)
	}

	return DeriveECDHESRaw(alg, z, apu, apv, keysize)
}
