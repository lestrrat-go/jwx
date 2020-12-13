package jwe

import (
	"crypto/aes"
	cryptocipher "crypto/cipher"
	"crypto/ecdsa"
	"crypto/rsa"

	"github.com/lestrrat-go/jwx/internal/keyconv"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe/internal/cipher"
	"github.com/lestrrat-go/jwx/jwe/internal/content_crypt"
	"github.com/lestrrat-go/jwx/jwe/internal/keyenc"
	"github.com/lestrrat-go/pdebug"
	"github.com/pkg/errors"
)

// Decrypter is responsible for taking various components to decrypt a message.
// its operation is not concurrency safe. You must provide locking yourself
type Decrypter struct {
	aad         []byte
	apu         []byte
	apv         []byte
	cipher      content_crypt.Cipher
	computedAad []byte
	ctalg       jwa.ContentEncryptionAlgorithm
	iv          []byte
	keyalg      jwa.KeyEncryptionAlgorithm
	keyiv       []byte
	keytag      []byte
	privkey     interface{}
	pubkey      interface{}
	tag         []byte
}

// NewDecrypter Creates a new Decrypter instance. You must supply the
// rest of parameters via their respective setter methods before
// calling Decrypt().
//
// privkey must be a private key in its "raw" format (i.e. something like
// *rsa.PrivateKey, instead of jwk.Key)
//
// You should consider this object immutable once you assign values to it.
func NewDecrypter(keyalg jwa.KeyEncryptionAlgorithm, ctalg jwa.ContentEncryptionAlgorithm, privkey interface{}) *Decrypter {
	return &Decrypter{
		ctalg:   ctalg,
		keyalg:  keyalg,
		privkey: privkey,
	}
}

func (d *Decrypter) AgreementPartyUInfo(apu []byte) *Decrypter {
	d.apu = apu
	return d
}

func (d *Decrypter) AgreementPartyVInfo(apv []byte) *Decrypter {
	d.apv = apv
	return d
}

func (d *Decrypter) AuthenticatedData(aad []byte) *Decrypter {
	d.aad = aad
	return d
}

func (d *Decrypter) ComputedAuthenticatedData(aad []byte) *Decrypter {
	d.computedAad = aad
	return d
}

func (d *Decrypter) ContentEncryptionAlgorithm(ctalg jwa.ContentEncryptionAlgorithm) *Decrypter {
	d.ctalg = ctalg
	return d
}

func (d *Decrypter) InitializationVector(iv []byte) *Decrypter {
	d.iv = iv
	return d
}

func (d *Decrypter) KeyInitializationVector(keyiv []byte) *Decrypter {
	d.keyiv = keyiv
	return d
}

func (d *Decrypter) KeyTag(keytag []byte) *Decrypter {
	d.keytag = keytag
	return d
}

// PublicKey sets the public key to be used in decoding EC based encryptions.
// The key must be in its "raw" format (i.e. *ecdsa.PublicKey, instead of jwk.Key)
func (d *Decrypter) PublicKey(pubkey interface{}) *Decrypter {
	d.pubkey = pubkey
	return d
}

func (d *Decrypter) Tag(tag []byte) *Decrypter {
	d.tag = tag
	return d
}

func (d *Decrypter) ContentCipher() (content_crypt.Cipher, error) {
	if d.cipher == nil {
		switch d.ctalg {
		case jwa.A128GCM, jwa.A192GCM, jwa.A256GCM, jwa.A128CBC_HS256, jwa.A192CBC_HS384, jwa.A256CBC_HS512:
			cipher, err := cipher.NewAES(d.ctalg)
			if err != nil {
				return nil, errors.Wrapf(err, `failed to build content cipher for %s`, d.ctalg)
			}
			d.cipher = cipher
		default:
			return nil, errors.Errorf(`invalid content cipher algorithm (%s)`, d.ctalg)
		}
	}

	return d.cipher, nil
}

func (d *Decrypter) Decrypt(recipientKey, ciphertext []byte) (plaintext []byte, err error) {
	if pdebug.Enabled {
		g := pdebug.Marker("Decrypter.Decrypt").BindError(&err)
		defer g.End()
	}

	cek, keyerr := d.DecryptKey(recipientKey)
	if keyerr != nil {
		err = errors.Wrap(keyerr, `failed to decrypt key`)
		return
	}

	cipher, ciphererr := d.ContentCipher()
	if ciphererr != nil {
		err = errors.Wrap(ciphererr, `failed to fetch content crypt cipher`)
		return
	}

	computedAad := d.computedAad
	if d.aad != nil {
		computedAad = append(append(computedAad, '.'), d.aad...)
	}

	if pdebug.Enabled {
		pdebug.Printf("Calling cipher.Decrypt (cipher = %T, cek len = %d)", cipher, len(cek))
	}

	plaintext, err = cipher.Decrypt(cek, d.iv, ciphertext, d.tag, computedAad)
	if err != nil {
		err = errors.Wrap(err, `failed to decrypt payload`)
		return
	}

	if pdebug.Enabled {
		pdebug.Printf("Successfully decrypted payload")
	}
	return plaintext, nil
}

func (d *Decrypter) decryptSymmetricKey(recipientKey, cek []byte) ([]byte, error) {
	if pdebug.Enabled {
		pdebug.Printf("Detected symmetric key algorithm %s", d.keyalg)
	}

	switch d.keyalg {
	case jwa.DIRECT:
		if pdebug.Enabled {
			pdebug.Printf("Successfully decrypted symmetric key (key len = %d)", len(cek))
		}
		return cek, nil
	case jwa.A128KW, jwa.A192KW, jwa.A256KW:
		block, err := aes.NewCipher(cek)
		if err != nil {
			return nil, errors.Wrap(err, `failed to create new AES cipher`)
		}

		jek, err := keyenc.Unwrap(block, recipientKey)
		if err != nil {
			return nil, errors.Wrap(err, `failed to unwrap key`)
		}

		if pdebug.Enabled {
			pdebug.Printf("cek len = %d", len(cek))
			pdebug.Printf("Wrapped key len = %d", len(jek))
		}
		return jek, nil
	case jwa.A128GCMKW, jwa.A192GCMKW, jwa.A256GCMKW:
		if pdebug.Enabled {
			pdebug.Printf("cek len = %d", len(cek))
		}
		if len(d.iv) != 12 {
			return nil, errors.Errorf("GCM requires 96-bit iv, got %d", len(d.iv)*8)
		}
		if len(d.tag) != 16 {
			return nil, errors.Errorf("GCM requires 128-bit tag, got %d", len(d.tag)*8)
		}
		block, err := aes.NewCipher(cek)
		if err != nil {
			return nil, errors.Wrap(err, `failed to create new AES cipher`)
		}
		aesgcm, err := cryptocipher.NewGCM(block)
		if err != nil {
			return nil, errors.Wrap(err, `failed to create new GCM wrap`)
		}
		ciphertext := recipientKey[:]
		ciphertext = append(ciphertext, d.keytag...)
		jek, err := aesgcm.Open(nil, d.keyiv, ciphertext, nil)
		if err != nil {
			return nil, errors.Wrap(err, `failed to decode key`)
		}
		return jek, nil
	default:
		return nil, errors.Errorf("decrypt key: unsupported algorithm %s", d.keyalg)
	}
}

func (d *Decrypter) DecryptKey(recipientKey []byte) (cek []byte, err error) {
	if pdebug.Enabled {
		g := pdebug.Marker("Decrypter.DecryptKey").BindError(&err)
		defer g.End()
	}
	if d.keyalg.IsSymmetric() {
		var ok bool
		cek, ok = d.privkey.([]byte)
		if !ok {
			return nil, errors.Errorf("decrypt key: []byte is required as the key to build %s key decrypter (got %T)", d.keyalg, d.privkey)
		}

		return d.decryptSymmetricKey(recipientKey, cek)
	}

	k, err := d.BuildKeyDecrypter()
	if err != nil {
		return nil, errors.Wrap(err, `failed to build key decrypter`)
	}

	cek, err = k.Decrypt(recipientKey)
	if err != nil {
		return nil, errors.Wrap(err, `failed to decrypt key`)
	}

	if pdebug.Enabled {
		pdebug.Printf("Successfully decrypted key")
	}

	return cek, nil
}

func (d *Decrypter) BuildKeyDecrypter() (keyenc.Decrypter, error) {
	cipher, err := d.ContentCipher()
	if err != nil {
		return nil, errors.Wrap(err, `failed to fetch content crypt cipher`)
	}

	switch alg := d.keyalg; alg {
	case jwa.RSA1_5:
		var privkey rsa.PrivateKey
		if err := keyconv.RSAPrivateKey(&privkey, d.privkey); err != nil {
			return nil, errors.Wrapf(err, "*rsa.PrivateKey is required as the key to build %s key decrypter", alg)
		}

		return keyenc.NewRSAPKCS15Decrypt(alg, &privkey, cipher.KeySize()/2), nil
	case jwa.RSA_OAEP, jwa.RSA_OAEP_256:
		var privkey rsa.PrivateKey
		if err := keyconv.RSAPrivateKey(&privkey, d.privkey); err != nil {
			return nil, errors.Wrapf(err, "*rsa.PrivateKey is required as the key to build %s key decrypter", alg)
		}

		return keyenc.NewRSAOAEPDecrypt(alg, &privkey)
	case jwa.A128KW, jwa.A192KW, jwa.A256KW:
		sharedkey, ok := d.privkey.([]byte)
		if !ok {
			return nil, errors.Errorf("[]byte is required as the key to build %s key decrypter", alg)
		}

		return keyenc.NewAES(alg, sharedkey)
	case jwa.ECDH_ES, jwa.ECDH_ES_A128KW, jwa.ECDH_ES_A192KW, jwa.ECDH_ES_A256KW:
		var pubkey ecdsa.PublicKey
		if err := keyconv.ECDSAPublicKey(&pubkey, d.pubkey); err != nil {
			return nil, errors.Wrapf(err, "*ecdsa.PublicKey is required as the key to build %s key decrypter", alg)
		}

		var privkey ecdsa.PrivateKey
		if err := keyconv.ECDSAPrivateKey(&privkey, d.privkey); err != nil {
			return nil, errors.Wrapf(err, "*ecdsa.PrivateKey is required as the key to build %s key decrypter", alg)
		}

		return keyenc.NewECDHESDecrypt(alg, d.ctalg, &pubkey, d.apu, d.apv, &privkey), nil
	default:
		return nil, errors.Errorf(`unsupported algorithm for key decryption (%s)`, alg)
	}
}

/*

buildKeyDecrypter(d.keyalg, h2, d.privkey, cipher.KeySize())

func buildECDHESDecrypter(alg jwa.KeyEncryptionAlgorithm, h Headers, key interface{}) (keyenc.Decrypter, error) {
}
*/
