package jwk

import (
	"crypto/ecdsa"

	"github.com/lestrrat/go-jwx/jwa"
)

// NewEcdhesPublicKey creates a new JWK from a ECDH-ES public key
func NewEcdhesPublicKey(key *ecdsa.PublicKey, keyalg jwa.KeyEncryptionAlgorithm, contentalg jwa.ContentEncryptionAlgorithm, agvars ...[]byte) *EcdhesPublicKey {

	var apu, apv []byte
	switch len(agvars) {
	case 1:
		apu = agvars[0]
	case 2:
		apu = agvars[0]
		apv = agvars[1]
	}

	return &EcdhesPublicKey{
		PublicKey:         NewEcdsaPublicKey(key),
		KeyEncryption:     keyalg,
		ContentEncryption: contentalg,
		UInfo:             apu,
		VInfo:             apv,
	}
}
