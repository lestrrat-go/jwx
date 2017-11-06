package jwe

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"hash"

	"github.com/lestrrat/go-jwx/internal/concatkdf"
	"github.com/lestrrat/go-jwx/internal/debug"
	"github.com/lestrrat/go-jwx/jwa"
	"github.com/pkg/errors"
)

// NewKeyWrapEncrypt creates a key-wrap encryptor using AES-CGM.
// Although the name suggests otherwise, this does the decryption as well.
func NewKeyWrapEncrypt(alg jwa.KeyEncryptionAlgorithm, sharedkey []byte) (KeyWrapEncrypt, error) {
	return KeyWrapEncrypt{
		alg:       alg,
		sharedkey: sharedkey,
	}, nil
}

// Algorithm returns the key encryption algorithm being used
func (kw KeyWrapEncrypt) Algorithm() jwa.KeyEncryptionAlgorithm {
	return kw.alg
}

// Kid returns the key ID associated with this encrypter
func (kw KeyWrapEncrypt) Kid() string {
	return kw.KeyID
}

// KeyDecrypt decrypts the encrypted key using AES-CGM key unwrap
func (kw KeyWrapEncrypt) KeyDecrypt(enckey []byte) ([]byte, error) {
	block, err := aes.NewCipher(kw.sharedkey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create cipher from shared key")
	}

	cek, err := keyunwrap(block, enckey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unwrap data")
	}
	return cek, nil
}

// KeyEncrypt encrypts the given content encryption key
func (kw KeyWrapEncrypt) KeyEncrypt(cek []byte) (ByteSource, error) {
	block, err := aes.NewCipher(kw.sharedkey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create cipher from shared key")
	}
	encrypted, err := keywrap(block, cek)
	if err != nil {
		return nil, errors.Wrap(err, `keywrap: failed to wrap key`)
	}
	return ByteKey(encrypted), nil
}

// NewEcdhesKeyWrapEncrypt creates a new key encrypter based on ECDH-ES
func NewEcdhesKeyWrapEncrypt(alg jwa.KeyEncryptionAlgorithm, key *ecdsa.PublicKey) (*EcdhesKeyWrapEncrypt, error) {
	generator, err := NewEcdhesKeyGenerate(alg, key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create key generator")
	}
	return &EcdhesKeyWrapEncrypt{
		algorithm: alg,
		generator: generator,
	}, nil
}

// Algorithm returns the key encryption algorithm being used
func (kw EcdhesKeyWrapEncrypt) Algorithm() jwa.KeyEncryptionAlgorithm {
	return kw.algorithm
}

// Kid returns the key ID associated with this encrypter
func (kw EcdhesKeyWrapEncrypt) Kid() string {
	return kw.KeyID
}

// KeyEncrypt encrypts the content encryption key using ECDH-ES
func (kw EcdhesKeyWrapEncrypt) KeyEncrypt(cek []byte) (ByteSource, error) {
	kg, err := kw.generator.KeyGenerate()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create key generator")
	}

	bwpk, ok := kg.(ByteWithECPrivateKey)
	if !ok {
		return nil, errors.New("key generator generated invalid key (expected ByteWithECPrivateKey)")
	}

	block, err := aes.NewCipher(bwpk.Bytes())
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate cipher from generated key")
	}

	jek, err := keywrap(block, cek)
	if err != nil {
		return nil, errors.Wrap(err, "failed to wrap data")
	}

	bwpk.ByteKey = ByteKey(jek)

	return bwpk, nil
}

// NewEcdhesKeyWrapDecrypt creates a new key decrypter using ECDH-ES
func NewEcdhesKeyWrapDecrypt(alg jwa.KeyEncryptionAlgorithm, pubkey *ecdsa.PublicKey, apu, apv []byte, privkey *ecdsa.PrivateKey) *EcdhesKeyWrapDecrypt {
	return &EcdhesKeyWrapDecrypt{
		algorithm: alg,
		apu:       apu,
		apv:       apv,
		privkey:   privkey,
		pubkey:    pubkey,
	}
}

// Algorithm returns the key encryption algorithm being used
func (kw EcdhesKeyWrapDecrypt) Algorithm() jwa.KeyEncryptionAlgorithm {
	return kw.algorithm
}

// KeyDecrypt decrypts the encrypted key using ECDH-ES
func (kw EcdhesKeyWrapDecrypt) KeyDecrypt(enckey []byte) ([]byte, error) {
	var keysize uint32
	switch kw.algorithm {
	case jwa.ECDH_ES_A128KW:
		keysize = 16
	case jwa.ECDH_ES_A192KW:
		keysize = 24
	case jwa.ECDH_ES_A256KW:
		keysize = 32
	default:
		return nil, errors.Wrap(ErrUnsupportedAlgorithm, "invalid ECDH-ES key wrap algorithm")
	}

	privkey := kw.privkey
	pubkey := kw.pubkey

	pubinfo := make([]byte, 4)
	binary.BigEndian.PutUint32(pubinfo, keysize*8)

	z, _ := privkey.PublicKey.Curve.ScalarMult(pubkey.X, pubkey.Y, privkey.D.Bytes())
	kdf := concatkdf.New(crypto.SHA256, []byte(kw.algorithm.String()), z.Bytes(), kw.apu, kw.apv, pubinfo, []byte{})
	kek := make([]byte, keysize)
	kdf.Read(kek)

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create cipher for ECDH-ES key wrap")
	}

	return keyunwrap(block, enckey)
}

// NewRSAOAEPKeyEncrypt creates a new key encrypter using RSA OAEP
func NewRSAOAEPKeyEncrypt(alg jwa.KeyEncryptionAlgorithm, pubkey *rsa.PublicKey) (*RSAOAEPKeyEncrypt, error) {
	switch alg {
	case jwa.RSA_OAEP, jwa.RSA_OAEP_256:
	default:
		return nil, errors.Wrap(ErrUnsupportedAlgorithm, "invalid RSA OAEP encrypt algorithm")
	}
	return &RSAOAEPKeyEncrypt{
		alg:    alg,
		pubkey: pubkey,
	}, nil
}

// NewRSAPKCSKeyEncrypt creates a new key encrypter using PKCS1v15
func NewRSAPKCSKeyEncrypt(alg jwa.KeyEncryptionAlgorithm, pubkey *rsa.PublicKey) (*RSAPKCSKeyEncrypt, error) {
	switch alg {
	case jwa.RSA1_5:
	default:
		return nil, errors.Wrap(ErrUnsupportedAlgorithm, "invalid RSA PKCS encrypt algorithm")
	}

	return &RSAPKCSKeyEncrypt{
		alg:    alg,
		pubkey: pubkey,
	}, nil
}

// Algorithm returns the key encryption algorithm being used
func (e RSAPKCSKeyEncrypt) Algorithm() jwa.KeyEncryptionAlgorithm {
	return e.alg
}

// Kid returns the key ID associated with this encrypter
func (e RSAPKCSKeyEncrypt) Kid() string {
	return e.KeyID
}

// Algorithm returns the key encryption algorithm being used
func (e RSAOAEPKeyEncrypt) Algorithm() jwa.KeyEncryptionAlgorithm {
	return e.alg
}

// Kid returns the key ID associated with this encrypter
func (e RSAOAEPKeyEncrypt) Kid() string {
	return e.KeyID
}

// KeyEncrypt encrypts the content encryption key using RSA PKCS1v15
func (e RSAPKCSKeyEncrypt) KeyEncrypt(cek []byte) (ByteSource, error) {
	if e.alg != jwa.RSA1_5 {
		return nil, errors.Wrap(ErrUnsupportedAlgorithm, "invalid RSA PKCS encrypt algorithm")
	}
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, e.pubkey, cek)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encrypt using PKCS1v15")
	}
	return ByteKey(encrypted), nil
}

// KeyEncrypt encrypts the content encryption key using RSA OAEP
func (e RSAOAEPKeyEncrypt) KeyEncrypt(cek []byte) (ByteSource, error) {
	var hash hash.Hash
	switch e.alg {
	case jwa.RSA_OAEP:
		hash = sha1.New()
	case jwa.RSA_OAEP_256:
		hash = sha256.New()
	default:
		return nil, errors.New("failed to generate key encrypter for RSA-OAEP: RSA_OAEP/RSA_OAEP_256 required")
	}
	encrypted, err := rsa.EncryptOAEP(hash, rand.Reader, e.pubkey, cek, []byte{})
	if err != nil {
		return nil, errors.Wrap(err, `failed to OAEP encrypt`)
	}
	return ByteKey(encrypted), nil
}

// NewRSAPKCS15KeyDecrypt creates a new decrypter using RSA PKCS1v15
func NewRSAPKCS15KeyDecrypt(alg jwa.KeyEncryptionAlgorithm, privkey *rsa.PrivateKey, keysize int) *RSAPKCS15KeyDecrypt {
	generator := NewRandomKeyGenerate(keysize * 2)
	return &RSAPKCS15KeyDecrypt{
		alg:       alg,
		privkey:   privkey,
		generator: generator,
	}
}

// Algorithm returns the key encryption algorithm being used
func (d RSAPKCS15KeyDecrypt) Algorithm() jwa.KeyEncryptionAlgorithm {
	return d.alg
}

// KeyDecrypt decryptes the encrypted key using RSA PKCS1v1.5
func (d RSAPKCS15KeyDecrypt) KeyDecrypt(enckey []byte) ([]byte, error) {
	if debug.Enabled {
		debug.Printf("START PKCS.KeyDecrypt")
	}
	// Hey, these notes and workarounds were stolen from go-jose
	defer func() {
		// DecryptPKCS1v15SessionKey sometimes panics on an invalid payload
		// because of an index out of bounds error, which we want to ignore.
		// This has been fixed in Go 1.3.1 (released 2014/08/13), the recover()
		// only exists for preventing crashes with unpatched versions.
		// See: https://groups.google.com/forum/#!topic/golang-dev/7ihX6Y6kx9k
		// See: https://code.google.com/p/go/source/detail?r=58ee390ff31602edb66af41ed10901ec95904d33
		_ = recover()
	}()

	// Perform some input validation.
	expectedlen := d.privkey.PublicKey.N.BitLen() / 8
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

	var err error

	bk, err := d.generator.KeyGenerate()
	if err != nil {
		return nil, errors.New("failed to generate key")
	}
	cek := bk.Bytes()

	// When decrypting an RSA-PKCS1v1.5 payload, we must take precautions to
	// prevent chosen-ciphertext attacks as described in RFC 3218, "Preventing
	// the Million Message Attack on Cryptographic Message Syntax". We are
	// therefore deliberatly ignoring errors here.
	err = rsa.DecryptPKCS1v15SessionKey(rand.Reader, d.privkey, enckey, cek)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt via PKCS1v15")
	}

	return cek, nil
}

// NewRSAOAEPKeyDecrypt creates a new key decrypter using RSA OAEP
func NewRSAOAEPKeyDecrypt(alg jwa.KeyEncryptionAlgorithm, privkey *rsa.PrivateKey) (*RSAOAEPKeyDecrypt, error) {
	switch alg {
	case jwa.RSA_OAEP, jwa.RSA_OAEP_256:
	default:
		return nil, errors.Wrap(ErrUnsupportedAlgorithm, "invalid RSA OAEP decrypt algorithm")
	}

	return &RSAOAEPKeyDecrypt{
		alg:     alg,
		privkey: privkey,
	}, nil
}

// Algorithm returns the key encryption algorithm being used
func (d RSAOAEPKeyDecrypt) Algorithm() jwa.KeyEncryptionAlgorithm {
	return d.alg
}

// KeyDecrypt decryptes the encrypted key using RSA OAEP
func (d RSAOAEPKeyDecrypt) KeyDecrypt(enckey []byte) ([]byte, error) {
	if debug.Enabled {
		debug.Printf("START OAEP.KeyDecrypt")
	}
	var hash hash.Hash
	switch d.alg {
	case jwa.RSA_OAEP:
		hash = sha1.New()
	case jwa.RSA_OAEP_256:
		hash = sha256.New()
	default:
		return nil, errors.New("failed to generate key encrypter for RSA-OAEP: RSA_OAEP/RSA_OAEP_256 required")
	}
	return rsa.DecryptOAEP(hash, rand.Reader, d.privkey, enckey, []byte{})
}

// Decrypt for DirectDecrypt does not do anything other than
// return a copy of the embedded key
func (d DirectDecrypt) Decrypt() ([]byte, error) {
	cek := make([]byte, len(d.Key))
	copy(cek, d.Key)
	return cek, nil
}

var keywrapDefaultIV = []byte{0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6}

const keywrapChunkLen = 8

func keywrap(kek cipher.Block, cek []byte) ([]byte, error) {
	if len(cek)%8 != 0 {
		return nil, ErrInvalidBlockSize
	}

	n := len(cek) / keywrapChunkLen
	r := make([][]byte, n)

	for i := 0; i < n; i++ {
		r[i] = make([]byte, keywrapChunkLen)
		copy(r[i], cek[i*keywrapChunkLen:])
	}

	buffer := make([]byte, keywrapChunkLen*2)
	tBytes := make([]byte, keywrapChunkLen)
	copy(buffer, keywrapDefaultIV)

	for t := 0; t < 6*n; t++ {
		copy(buffer[keywrapChunkLen:], r[t%n])

		kek.Encrypt(buffer, buffer)

		binary.BigEndian.PutUint64(tBytes, uint64(t+1))

		for i := 0; i < keywrapChunkLen; i++ {
			buffer[i] = buffer[i] ^ tBytes[i]
		}
		copy(r[t%n], buffer[keywrapChunkLen:])
	}

	out := make([]byte, (n+1)*keywrapChunkLen)
	copy(out, buffer[:keywrapChunkLen])
	for i := range r {
		copy(out[(i+1)*8:], r[i])
	}

	return out, nil
}

func keyunwrap(block cipher.Block, ciphertxt []byte) ([]byte, error) {
	if len(ciphertxt)%keywrapChunkLen != 0 {
		return nil, ErrInvalidBlockSize
	}

	n := (len(ciphertxt) / keywrapChunkLen) - 1
	r := make([][]byte, n)

	for i := range r {
		r[i] = make([]byte, keywrapChunkLen)
		copy(r[i], ciphertxt[(i+1)*keywrapChunkLen:])
	}

	buffer := make([]byte, keywrapChunkLen*2)
	tBytes := make([]byte, keywrapChunkLen)
	copy(buffer[:keywrapChunkLen], ciphertxt[:keywrapChunkLen])

	for t := 6*n - 1; t >= 0; t-- {
		binary.BigEndian.PutUint64(tBytes, uint64(t+1))

		for i := 0; i < keywrapChunkLen; i++ {
			buffer[i] = buffer[i] ^ tBytes[i]
		}
		copy(buffer[keywrapChunkLen:], r[t%n])

		block.Decrypt(buffer, buffer)

		copy(r[t%n], buffer[keywrapChunkLen:])
	}

	if subtle.ConstantTimeCompare(buffer[:keywrapChunkLen], keywrapDefaultIV) == 0 {
		return nil, errors.New("keywrap: failed to unwrap key")
	}

	out := make([]byte, n*keywrapChunkLen)
	for i := range r {
		copy(out[i*keywrapChunkLen:], r[i])
	}

	return out, nil
}
