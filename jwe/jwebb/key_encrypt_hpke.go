package jwebb

import (
	"crypto/hpke"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwe/internal/keygen"
)

// KeyEncryptHPKEKE performs HPKE key encryption per
// draft-ietf-jose-hpke-encrypt-16 (https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/16/).
// It encrypts the CEK using the HPKE ciphersuite determined by alg, with the
// content encryption algorithm calg bound into the HPKE info parameter.
func KeyEncryptHPKEKE(cek []byte, alg, calg string, pubkey any) (keygen.ByteSource, error) {
	// Try custom HPKE key encrypter (e.g., X448 from external modules)
	if enc, ok := pubkey.(HPKEKeyEncrypter); ok {
		return KeyEncryptHPKECustom(cek, alg, calg, enc)
	}

	kdf, aead, err := hpkeSuite(alg)
	if err != nil {
		return nil, fmt.Errorf(`HPKE key encrypt: %w`, err)
	}

	pk, err := hpkePublicKey(alg, pubkey)
	if err != nil {
		return nil, fmt.Errorf(`HPKE key encrypt: %w`, err)
	}

	info := hpkeKEInfo(calg)

	enc, sender, err := hpke.NewSender(pk, kdf, aead, info)
	if err != nil {
		return nil, fmt.Errorf(`HPKE key encrypt: failed to create sender: %w`, err)
	}

	// AAD is empty for key encryption mode per spec
	sealedCEK, err := sender.Seal(nil, cek)
	if err != nil {
		return nil, fmt.Errorf(`HPKE key encrypt: failed to seal CEK: %w`, err)
	}

	return keygen.ByteWithEncapsulatedKey{
		ByteKey:    keygen.ByteKey(sealedCEK),
		Ciphertext: enc,
	}, nil
}
