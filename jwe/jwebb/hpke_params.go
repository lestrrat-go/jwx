package jwebb

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hpke"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/internal/tokens"
)

type hpkeCiphersuite struct {
	curve ecdh.Curve
	kdf   hpke.KDF
	aead  hpke.AEAD
}

var hpkeSuites = map[string]hpkeCiphersuite{
	tokens.HPKE_0_KE: {ecdh.P256(), hpke.HKDFSHA256(), hpke.AES128GCM()},
	tokens.HPKE_1_KE: {ecdh.P384(), hpke.HKDFSHA384(), hpke.AES256GCM()},
	tokens.HPKE_2_KE: {ecdh.P521(), hpke.HKDFSHA512(), hpke.AES256GCM()},
	tokens.HPKE_3_KE: {ecdh.X25519(), hpke.HKDFSHA256(), hpke.AES128GCM()},
	tokens.HPKE_4_KE: {ecdh.X25519(), hpke.HKDFSHA256(), hpke.ChaCha20Poly1305()},
	tokens.HPKE_7_KE: {ecdh.P256(), hpke.HKDFSHA256(), hpke.AES256GCM()},
}

func hpkeSuite(alg string) (hpke.KDF, hpke.AEAD, error) {
	cs, ok := hpkeSuites[alg]
	if !ok {
		return nil, nil, fmt.Errorf(`unsupported HPKE algorithm: %s`, alg)
	}
	return cs.kdf, cs.aead, nil
}

// hpkeKEInfo builds the HPKE info parameter for Key Encryption mode
// per draft-ietf-jose-hpke-encrypt-16
// (https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/16/):
//
//	"JOSE-HPKE rcpt" || 0xFF || enc_value || 0xFF
func hpkeKEInfo(calg string) []byte {
	prefix := []byte("JOSE-HPKE rcpt")
	calgBytes := []byte(calg)
	info := make([]byte, 0, len(prefix)+1+len(calgBytes)+1)
	info = append(info, prefix...)
	info = append(info, 0xFF)
	info = append(info, calgBytes...)
	info = append(info, 0xFF)
	return info
}

// hpkePublicKey converts a raw key to hpke.PublicKey.
// Accepts *ecdh.PublicKey and *ecdsa.PublicKey (converted via keyconv).
func hpkePublicKey(alg string, key any) (hpke.PublicKey, error) {
	ecdhPub, err := toECDHPublicKey(alg, key)
	if err != nil {
		return nil, err
	}
	return hpke.NewDHKEMPublicKey(ecdhPub)
}

// hpkePrivateKey converts a raw key to hpke.PrivateKey.
// Accepts *ecdh.PrivateKey and *ecdsa.PrivateKey (converted via keyconv).
func hpkePrivateKey(alg string, key any) (hpke.PrivateKey, error) {
	ecdhPriv, err := toECDHPrivateKey(alg, key)
	if err != nil {
		return nil, err
	}
	return hpke.NewDHKEMPrivateKey(ecdhPriv)
}

func toECDHPublicKey(alg string, key any) (*ecdh.PublicKey, error) {
	cs, ok := hpkeSuites[alg]
	if !ok {
		return nil, fmt.Errorf(`unsupported HPKE algorithm: %s`, alg)
	}

	switch k := key.(type) {
	case *ecdh.PublicKey:
		if k.Curve() != cs.curve {
			return nil, fmt.Errorf(`HPKE %s: expected %s key, got %s`, alg, cs.curve, k.Curve())
		}
		return k, nil
	case *ecdh.PrivateKey:
		pub := k.PublicKey()
		if pub.Curve() != cs.curve {
			return nil, fmt.Errorf(`HPKE %s: expected %s key, got %s`, alg, cs.curve, pub.Curve())
		}
		return pub, nil
	case *ecdsa.PublicKey:
		ecdhKey, err := k.ECDH()
		if err != nil {
			return nil, fmt.Errorf(`HPKE %s: failed to convert ECDSA to ECDH public key: %w`, alg, err)
		}
		if ecdhKey.Curve() != cs.curve {
			return nil, fmt.Errorf(`HPKE %s: expected %s key, got %s`, alg, cs.curve, ecdhKey.Curve())
		}
		return ecdhKey, nil
	case *ecdsa.PrivateKey:
		ecdhKey, err := k.PublicKey.ECDH()
		if err != nil {
			return nil, fmt.Errorf(`HPKE %s: failed to convert ECDSA to ECDH public key: %w`, alg, err)
		}
		if ecdhKey.Curve() != cs.curve {
			return nil, fmt.Errorf(`HPKE %s: expected %s key, got %s`, alg, cs.curve, ecdhKey.Curve())
		}
		return ecdhKey, nil
	default:
		return nil, fmt.Errorf(`HPKE %s: unsupported key type %T`, alg, key)
	}
}

func toECDHPrivateKey(alg string, key any) (*ecdh.PrivateKey, error) {
	cs, ok := hpkeSuites[alg]
	if !ok {
		return nil, fmt.Errorf(`unsupported HPKE algorithm: %s`, alg)
	}

	switch k := key.(type) {
	case *ecdh.PrivateKey:
		if k.PublicKey().Curve() != cs.curve {
			return nil, fmt.Errorf(`HPKE %s: expected %s key, got %s`, alg, cs.curve, k.PublicKey().Curve())
		}
		return k, nil
	case *ecdsa.PrivateKey:
		ecdhKey, err := k.ECDH()
		if err != nil {
			return nil, fmt.Errorf(`HPKE %s: failed to convert ECDSA to ECDH: %w`, alg, err)
		}
		if ecdhKey.PublicKey().Curve() != cs.curve {
			return nil, fmt.Errorf(`HPKE %s: expected %s key, got %s`, alg, cs.curve, ecdhKey.PublicKey().Curve())
		}
		return ecdhKey, nil
	default:
		return nil, fmt.Errorf(`HPKE %s: unsupported private key type %T (need *ecdh.PrivateKey or *ecdsa.PrivateKey)`, alg, key)
	}
}
