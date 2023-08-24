//go:build jwx_es256k
// +build jwx_es256k

package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"sync"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lestrrat-go/blackmagic"
	"github.com/lestrrat-go/jwx/v2/internal/ecutil"
	"github.com/lestrrat-go/jwx/v2/jwa"
)

func init() {
	ecutil.RegisterCurve(secp256k1.S256(), jwa.Secp256k1)

	AddKeyFromRaw(ChainedKeyFromRawFunc(secp256k1FromRaw))
	AddRawFromKey(ChainedRawFromKeyFunc(secp256k1Raw))
	AddASN1Encoder(ChainedASN1EncodeFunc(secp256k1ASN1Encode))
	AddASN1Decoder(ChainedASN1DecodeFunc(secp256k1ASN1Decode))
}

var secp256k1OID = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
var secp256k1PkPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 32+1) // 32 bytes + 1
	},
}

func getPkBuf(size int) []byte {
	buf := secp256k1PkPool.Get().([]byte)
	if cap(buf) < size {
		buf = make([]byte, size)
	} else {
		buf = buf[:size]
	}
	return buf
}

func releasePkBuf(buf []byte) {
	// XXX Replace this with clear() when we remove support for go < 1.21
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(0)
	}

	secp256k1PkPool.Put(buf)
}

type secp256k1ASN1PrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

type secp256k1ASN1PublicKey struct {
	Algorithm pkix.AlgorithmIdentifier
	BitString asn1.BitString
}

func secp256k1ASN1Encode(n ASN1Encoder, key Key) (string, []byte, error) {
	switch key := key.(type) {
	case ECDSAPrivateKey:
		if key.Crv() == jwa.Secp256k1 {
			var raw secp256k1.PrivateKey
			if err := Raw(key, &raw); err != nil {
				return "", nil, fmt.Errorf(`failed to convert jwk.Key into raw key: %w`, err)
			}
			return secp256k1EncodePrivateKey(&raw)
		}
	case ECDSAPublicKey:
		if key.Crv() == jwa.Secp256k1 {
			var raw secp256k1.PublicKey
			if err := Raw(key, &raw); err != nil {
				return "", nil, fmt.Errorf(`failed to convert jwk.Key into raw key: %w`, err)
			}
			return secp256k1EncodePublicKey(&raw)
		}
	}

	return n.ASN1Encode(key)
}

func secp256k1ASN1Decode(n ASN1Decoder, buf []byte) (interface{}, []byte, error) {
	block, rest := pem.Decode(buf)
	if block == nil {
		return nil, buf, fmt.Errorf(`jwk: PEM block decoded to nil`)
	}

	if block.Type == pmECPrivateKey {
		var priv secp256k1ASN1PrivateKey
		// for 1-3, we're going to believe that this may have been
		// another EC key that can be decoded by the next decoder
		if _, err := asn1.Unmarshal(block.Bytes, &priv); err != nil { // (1)
			return n.ASN1Decode(buf)
		}

		if !priv.NamedCurveOID.Equal(secp256k1OID) { // (2)
			return n.ASN1Decode(buf)
		}

		if priv.Version != 1 { // (3)
			return n.ASN1Decode(buf)
		}

		key := secp256k1.PrivKeyFromBytes(priv.PrivateKey)
		return key, rest, nil
	}
	// All other cases including secp256k1 public key can be handled
	// by the default handler
	return n.ASN1Decode(buf)
}

func secp256k1EncodePrivateKey(key *secp256k1.PrivateKey) (string, []byte, error) {
	asECDSA := key.ToECDSA()
	size := (asECDSA.Curve.Params().N.BitLen() + 7) / 8
	pkbuf := getPkBuf(size)
	defer releasePkBuf(pkbuf)

	buf, err := asn1.Marshal(secp256k1ASN1PrivateKey{
		Version:       1,
		PrivateKey:    asECDSA.D.FillBytes(pkbuf),
		NamedCurveOID: secp256k1OID,
		PublicKey: asn1.BitString{
			Bytes: elliptic.Marshal(asECDSA.Curve, asECDSA.X, asECDSA.Y),
		},
	})
	if err != nil {
		return "", nil, fmt.Errorf(`failed to marshal secp256k1 private key: %w`, err)
	}

	return pmECPrivateKey, buf, nil
}

func secp256k1EncodePublicKey(key *secp256k1.PublicKey) (string, []byte, error) {
	asECDSA := key.ToECDSA()

	pkbuf := elliptic.Marshal(asECDSA.Curve, asECDSA.X, asECDSA.Y)

	oidBuf, err := asn1.Marshal(secp256k1OID)
	if err != nil {
		return "", nil, fmt.Errorf(`failed to marshal oid in ASN.1 format`)
	}

	buf, err := asn1.Marshal(secp256k1ASN1PublicKey{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: secp256k1OID,
			Parameters: asn1.RawValue{
				FullBytes: oidBuf,
			},
		},
		BitString: asn1.BitString{
			Bytes:     pkbuf,
			BitLength: 8 * len(pkbuf),
		},
	})
	if err != nil {
		return "", nil, fmt.Errorf(`failed to marshal secp256k1 public key: %w`, err)
	}

	return pmPublicKey, buf, nil
}

func secp256k1FromRaw(nextKFR KeyFromRawer, key interface{}) (Key, error) {
	switch key := key.(type) {
	case *secp256k1.PrivateKey:
		return nextKFR.KeyFromRaw(key.ToECDSA())
	case *secp256k1.PublicKey:
		return nextKFR.KeyFromRaw(key.ToECDSA())
	default:
		return nextKFR.KeyFromRaw(key)
	}
}

func secp256k1Raw(nextRFK RawFromKeyer, key Key, raw interface{}) error {
	// for secp256k1Raw keys, you can either create a ecdsa.* key or a
	// secp256k1.* key.
	switch raw := raw.(type) {
	case *secp256k1.PrivateKey:
		// we first get a ecdsa.PrivateKey, then convert it to secp256k1.PrivateKey
		var ecdsaKey ecdsa.PrivateKey
		if err := key.Raw(&ecdsaKey); err != nil {
			return fmt.Errorf(`failed to convert JWK into raw ecdsa.PrivateKey: %w`, err)
		}
		// Make sure the curve is secp256k1
		if ecdsaKey.Curve.Params().Name != secp256k1.S256().Params().Name {
			return fmt.Errorf(`invalid curve for secp256k1: %s`, ecdsaKey.Curve.Params().Name)
		}
		return blackmagic.AssignIfCompatible(raw, secp256k1.PrivKeyFromBytes(ecdsaKey.D.Bytes()))
	case *secp256k1.PublicKey:
		// we first get a ecdsa.PublicKey, then convert it to secp256k1.PublicKey
		var ecdsaKey ecdsa.PublicKey
		if err := key.Raw(&ecdsaKey); err != nil {
			return fmt.Errorf(`failed to convert JWK into raw ecdsa.PublicKey: %w`, err)
		}
		// Make sure the curve is secp256k1
		if ecdsaKey.Curve.Params().Name != secp256k1.S256().Params().Name {
			return fmt.Errorf(`invalid curve for secp256k1: %s`, ecdsaKey.Curve.Params().Name)
		}
		var x secp256k1.FieldVal
		var y secp256k1.FieldVal
		x.SetByteSlice(ecdsaKey.X.Bytes())
		y.SetByteSlice(ecdsaKey.Y.Bytes())
		return blackmagic.AssignIfCompatible(raw, secp256k1.NewPublicKey(&x, &y))
	default:
		return nextRFK.RawFromKey(key, raw)
	}
}
