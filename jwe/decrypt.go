package jwe

import (
	"crypto/ecdsa"
	"crypto/rsa"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe/internal/keyenc"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"
)

func buildRSA15Decrypter(alg jwa.KeyEncryptionAlgorithm, _ Headers, key interface{}, keysize int) (keyenc.Decrypter, error) {
	var privkey *rsa.PrivateKey
	switch v := key.(type) {
	case rsa.PrivateKey:
		privkey = &v
	case *rsa.PrivateKey:
		privkey = v
	default:
		return nil, errors.Errorf("*rsa.PrivateKey is required as the key to build %s key decrypter", alg)
	}

	return keyenc.NewRSAPKCS15Decrypt(alg, privkey, keysize/2), nil
}

func buildRSAOAEPDecrypter(alg jwa.KeyEncryptionAlgorithm, _ Headers, key interface{}, _ int) (keyenc.Decrypter, error) {
	var privkey *rsa.PrivateKey
	switch v := key.(type) {
	case rsa.PrivateKey:
		privkey = &v
	case *rsa.PrivateKey:
		privkey = v
	default:
		return nil, errors.Errorf("*rsa.PrivateKey is required as the key to build %s key decrypter", alg)
	}

	return keyenc.NewRSAOAEPDecrypt(alg, privkey)
}

func buildKeywrapDecrypter(alg jwa.KeyEncryptionAlgorithm, _ Headers, key interface{}, _ int) (keyenc.Decrypter, error) {
	sharedkey, ok := key.([]byte)
	if !ok {
		return nil, errors.Errorf("[]byte is required as the key to build %s key decrypter", alg)
	}
	return keyenc.NewAESCGM(alg, sharedkey)
}

func buildECDHESDecrypter(alg jwa.KeyEncryptionAlgorithm, h Headers, key interface{}, keysize int) (keyenc.Decrypter, error) {
	epkif, ok := h.Get(EphemeralPublicKeyKey)
	if !ok {
		return nil, errors.New("failed to get 'epk' field")
	}
	if epkif == nil {
		return nil, errors.Errorf("'epk' header is required as the key to build %s key decrypter", alg)
	}

	epk, ok := epkif.(jwk.ECDSAPublicKey)
	if !ok {
		return nil, errors.Errorf("'epk' header is required as the key to build %s key decrypter", alg)
	}

	var pubkey interface{}
	if err := epk.Raw(&pubkey); err != nil {
		return nil, errors.Wrap(err, "failed to get public key")
	}

	privkey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.Errorf("*ecdsa.PrivateKey is required as the key to build %s key decrypter", alg)
	}
	var apuData, apvData []byte
	apu := h.AgreementPartyUInfo()
	if apu.Len() > 0 {
		apuData = apu.Bytes()
	}

	apv := h.AgreementPartyVInfo()
	if apv.Len() > 0 {
		apuData = apu.Bytes()
	}

	return keyenc.NewECDHESDecrypt(alg, h.ContentEncryption(), pubkey.(*ecdsa.PublicKey), apuData, apvData, privkey), nil
}

// buildKeyDecrypter creates a new KeyDecrypter instance from the given
// parameters. It is used by the Message.Decrypt method to create
// key decrypter(s) from the given message. `keysize` is only used by
// some decrypters. Pass the value from ContentCipher.KeySize().
func buildKeyDecrypter(alg jwa.KeyEncryptionAlgorithm, h Headers, key interface{}, keysize int) (keyenc.Decrypter, error) {
	switch alg {
	case jwa.RSA1_5:
		return buildRSA15Decrypter(alg, h, key, keysize)
	case jwa.RSA_OAEP, jwa.RSA_OAEP_256:
		return buildRSAOAEPDecrypter(alg, h, key, keysize)
	case jwa.A128KW, jwa.A192KW, jwa.A256KW:
		return buildKeywrapDecrypter(alg, h, key, keysize)
	case jwa.ECDH_ES, jwa.ECDH_ES_A128KW, jwa.ECDH_ES_A192KW, jwa.ECDH_ES_A256KW:
		return buildECDHESDecrypter(alg, h, key, keysize)
	}

	return nil, errors.Errorf(`unsupported algorithm for key decryption (%s)`, alg)
}
