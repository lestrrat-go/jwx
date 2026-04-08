package jwebb

import (
	"crypto/hpke"
	"fmt"
)

// KeyDecryptHPKEKE performs HPKE key decryption per
// draft-ietf-jose-hpke-encrypt-16 (https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/16/).
// encryptedCEK is the HPKE-sealed CEK from the JWE Encrypted Key field.
// ek is the HPKE encapsulated key from the "ek" header field.
func KeyDecryptHPKEKE(encryptedCEK []byte, alg, calg string, privkey any, ek []byte) ([]byte, error) {
	// Try custom HPKE key decrypter (e.g., X448 from external modules)
	if dec, ok := privkey.(HPKEKeyDecrypter); ok {
		return KeyDecryptHPKECustom(encryptedCEK, alg, calg, dec, ek)
	}

	kdf, aead, err := hpkeSuite(alg)
	if err != nil {
		return nil, fmt.Errorf(`HPKE key decrypt: %w`, err)
	}

	sk, err := hpkePrivateKey(alg, privkey)
	if err != nil {
		return nil, fmt.Errorf(`HPKE key decrypt: %w`, err)
	}

	info := hpkeKEInfo(calg)

	recipient, err := hpke.NewRecipient(ek, sk, kdf, aead, info)
	if err != nil {
		return nil, fmt.Errorf(`HPKE key decrypt: failed to create recipient: %w`, err)
	}

	// AAD is empty for key encryption mode per spec
	cek, err := recipient.Open(nil, encryptedCEK)
	if err != nil {
		return nil, fmt.Errorf(`HPKE key decrypt: failed to open sealed CEK: %w`, err)
	}

	return cek, nil
}
