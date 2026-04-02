// Package ed448 provides Ed448 signing, verification, and JWK support for the jwx library.
//
// Ed448 is not included in the main jwx module because Go's standard library
// does not support Ed448, requiring the external github.com/cloudflare/circl
// module. To avoid adding this dependency for all users, Ed448 support is
// provided as a separate module.
//
// To enable Ed448 support, import this package for its side effects:
//
//	import _ "github.com/lestrrat-go/jwx/v3/ed448"
//
// This registers Ed448 signing/verification (via dsig-circl-ed448), JWK key
// import/export, and algorithm-for-key-type mappings. After importing,
// jwa.EdDSAEd448() can be used with jws.Sign, jws.Verify, jwk.Import, etc.
package ed448

import (
	"bytes"
	"fmt"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwk/jwkunsafe"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jws/jwsbb"

	// Import dsig-circl-ed448 for side effects: registers Ed448 sign/verify
	// with dsig as a Custom family algorithm.
	_ "github.com/lestrrat-go/dsig-circl-ed448"
)

func init() {
	// Register Ed448 as a known signature algorithm in jwa
	jwa.RegisterSignatureAlgorithm(jwa.EdDSAEd448())

	// Register Ed448 as valid algorithm for OKP key type
	jws.RegisterAlgorithmForKeyType(jwa.OKP(), jwa.EdDSAEd448())

	// Register signer/verifier that handle JWK key unwrapping.
	// The dsig-circl-ed448 signer only accepts raw ed448 keys,
	// so we need this layer to convert JWK keys before dispatch.
	if err := jws.RegisterSigner(jwa.EdDSAEd448(), ed448Signer{}); err != nil {
		panic(fmt.Sprintf("ed448: failed to register signer: %s", err))
	}
	if err := jws.RegisterVerifier(jwa.EdDSAEd448(), ed448Verifier{}); err != nil {
		panic(fmt.Sprintf("ed448: failed to register verifier: %s", err))
	}

	// Register JWK exporter for OKP:Ed448 keys (JWK → raw ed448 key)
	jwk.RegisterKeyExporter(jwk.KeyKind("OKP:Ed448"), jwk.KeyExportFunc(exportEd448Key))

	// Register raw key importer for Ed448 keys
	jwk.RegisterOKPRawKeyImporter(importEd448RawKey)

	// Register jwk.Import handlers for Ed448 key types (raw ed448 key → JWK)
	f := jwk.KeyImportFunc(importOKPEd448Key)
	jwk.RegisterKeyImporter(ed448.PublicKey(nil), f)
	jwk.RegisterKeyImporter(ed448.PrivateKey(nil), f)
}

// --- Signer/Verifier (JWK key unwrapping) ---

type ed448Signer struct{}

func (ed448Signer) Algorithm() jwa.SignatureAlgorithm { return jwa.EdDSAEd448() }

func (ed448Signer) Sign(key any, payload []byte) ([]byte, error) {
	var privkey ed448.PrivateKey
	if err := ed448PrivateKey(&privkey, key); err != nil {
		return nil, fmt.Errorf(`ed448.Sign: %w`, err)
	}
	return jwsbb.Sign(privkey, "Ed448", payload, nil)
}

type ed448Verifier struct{}

func (ed448Verifier) Verify(key any, payload, signature []byte) error {
	var pubkey ed448.PublicKey
	if err := ed448PublicKey(&pubkey, key); err != nil {
		return fmt.Errorf(`ed448.Verify: %w`, err)
	}
	return jwsbb.Verify(pubkey, "Ed448", payload, signature)
}

// --- Key conversion ---

func ed448PrivateKey(dst *ed448.PrivateKey, src any) error {
	if jwkKey, ok := src.(jwk.Key); ok {
		var raw ed448.PrivateKey
		if err := jwk.Export(jwkKey, &raw); err != nil {
			return fmt.Errorf(`failed to produce ed448.PrivateKey from %T: %w`, src, err)
		}
		*dst = raw
		return nil
	}

	switch src := src.(type) {
	case ed448.PrivateKey:
		*dst = src
	case *ed448.PrivateKey:
		*dst = *src
	default:
		return fmt.Errorf(`expected ed448.PrivateKey, got %T`, src)
	}
	return nil
}

func ed448PublicKey(dst *ed448.PublicKey, src any) error {
	if jwkKey, ok := src.(jwk.Key); ok {
		pk, err := jwk.PublicRawKeyOf(jwkKey)
		if err != nil {
			return fmt.Errorf(`failed to produce public key from %T: %w`, src, err)
		}
		src = pk
	}

	switch key := src.(type) {
	case ed448.PrivateKey:
		src = key.Public()
	case *ed448.PrivateKey:
		src = key.Public()
	}

	switch src := src.(type) {
	case ed448.PublicKey:
		*dst = src
	case *ed448.PublicKey:
		*dst = *src
	default:
		return fmt.Errorf(`expected ed448.PublicKey, got %T`, src)
	}
	return nil
}

// --- JWK key export (JWK → raw ed448 key) ---

func exportEd448Key(key jwk.Key, _ any) (any, error) {
	switch key := key.(type) {
	case jwk.OKPPrivateKey:
		x, ok := key.X()
		if !ok {
			return nil, fmt.Errorf(`missing "x" field`)
		}
		d, ok := key.D()
		if !ok {
			return nil, fmt.Errorf(`missing "d" field`)
		}
		if len(d) != ed448.SeedSize {
			return nil, fmt.Errorf(`ed448: wrong private key seed size %d (expected %d)`, len(d), ed448.SeedSize)
		}
		ret := ed448.NewKeyFromSeed(d)
		pub := ret.Public().(ed448.PublicKey) //nolint:forcetypeassert
		if !bytes.Equal(x, pub) {
			return nil, fmt.Errorf(`ed448: invalid x value given d value`)
		}
		return ret, nil
	case jwk.OKPPublicKey:
		x, ok := key.X()
		if !ok {
			return nil, fmt.Errorf(`missing "x" field`)
		}
		if len(x) != ed448.PublicKeySize {
			return nil, fmt.Errorf(`ed448: wrong public key size %d (expected %d)`, len(x), ed448.PublicKeySize)
		}
		return ed448.PublicKey(x), nil
	default:
		return nil, jwk.ContinueError()
	}
}

// --- JWK raw key import ---

func importEd448RawKey(key any) (jwa.EllipticCurveAlgorithm, []byte, []byte, bool) {
	switch k := key.(type) {
	case ed448.PublicKey:
		return jwa.Ed448(), []byte(k), nil, true
	case ed448.PrivateKey:
		pub := k.Public().(ed448.PublicKey) //nolint:forcetypeassert
		return jwa.Ed448(), []byte(pub), k.Seed(), true
	}
	return jwa.InvalidEllipticCurve(), nil, nil, false
}

func importOKPEd448Key(src any) (jwk.Key, error) {
	switch k := src.(type) {
	case ed448.PrivateKey:
		key, err := jwkunsafe.NewKey(jwa.OKP())
		if err != nil {
			return nil, fmt.Errorf(`failed to create OKP private key: %w`, err)
		}
		pub := k.Public().(ed448.PublicKey) //nolint:forcetypeassert
		if err := key.Set(jwk.OKPCrvKey, jwa.Ed448()); err != nil {
			return nil, err
		}
		if err := key.Set(jwk.OKPXKey, []byte(pub)); err != nil {
			return nil, err
		}
		if err := key.Set(jwk.OKPDKey, k.Seed()); err != nil {
			return nil, err
		}
		return key, nil
	case ed448.PublicKey:
		key, err := jwkunsafe.NewPublicKey(jwa.OKP())
		if err != nil {
			return nil, fmt.Errorf(`failed to create OKP public key: %w`, err)
		}
		if err := key.Set(jwk.OKPCrvKey, jwa.Ed448()); err != nil {
			return nil, err
		}
		if err := key.Set(jwk.OKPXKey, []byte(k)); err != nil {
			return nil, err
		}
		return key, nil
	default:
		return nil, fmt.Errorf(`cannot convert key type %T to OKP jwk.Key`, src)
	}
}
