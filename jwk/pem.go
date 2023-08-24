package jwk

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"
)

const (
	pmPrivateKey    = `PRIVATE KEY`
	pmPublicKey     = `PUBLIC KEY`
	pmECPrivateKey  = `EC PRIVATE KEY`
	pmRSAPublicKey  = `RSA PUBLIC KEY`
	pmRSAPrivateKey = `RSA PRIVATE KEY`
)

// ASN1Decoder decodes a given byte sequence into a key.
type ASN1Decoder interface {
	ASN1Decode([]byte) (interface{}, []byte, error)
}

type ChainedASN1Decoder interface {
	Next(ASN1Decoder, []byte) (interface{}, []byte, error)
}

type ChainedASN1DecodeFunc func(ASN1Decoder, []byte) (interface{}, []byte, error)

func (fn ChainedASN1DecodeFunc) Next(n ASN1Decoder, src []byte) (interface{}, []byte, error) {
	return fn(n, src)
}

type chainedASN1Decoder struct {
	mu   sync.RWMutex
	list []ChainedASN1Decoder
}

func (c *chainedASN1Decoder) Add(d ChainedASN1Decoder) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.list = append(c.list, d)
}

func (c *chainedASN1Decoder) Next(src []byte) (interface{}, []byte, error) {
	c.mu.RLock()
	llist := len(c.list)
	c.mu.RUnlock()
	st := &chainedASN1DecoderCallState{parent: c, current: llist}
	return st.ASN1Decode(src)
}

type chainedASN1DecoderCallState struct {
	current int
	parent  *chainedASN1Decoder
}

func (st *chainedASN1DecoderCallState) ASN1Decode(src []byte) (interface{}, []byte, error) {
	idx := st.current - 1

	st.parent.mu.RLock()
	defer st.parent.mu.RUnlock()

	llist := len(st.parent.list)
	if idx < 0 || idx >= llist {
		return nil, nil, fmt.Errorf(`failed to decode PEM data`)
	}

	st.current = idx

	d := st.parent.list[idx]
	return d.Next(st, src)
}

type NextASN1Decoder func([]byte) (interface{}, []byte, error)

func AddASN1Decoder(dec ChainedASN1Decoder) {
	chainedASN1D.Add(dec)
}

var chainedASN1D = &chainedASN1Decoder{
	list: []ChainedASN1Decoder{ChainedASN1DecodeFunc(asn1Decode)},
}

type chainedASN1Encoder struct {
	mu   sync.RWMutex
	list []ASN1Encoder
}

func (c *chainedASN1Encoder) Add(e ASN1Encoder) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.list = append(c.list, e)
}

func (c *chainedASN1Encoder) Next(key Key) (string, []byte, error) {
	c.mu.RLock()
	llist := len(c.list)
	c.mu.RUnlock()
	st := &chainedASN1EncoderCallState{parent: c, current: llist}
	return st.Next(key)
}

type chainedASN1EncoderCallState struct {
	current int
	parent  *chainedASN1Encoder
}

func (st *chainedASN1EncoderCallState) Next(key Key) (string, []byte, error) {
	idx := st.current - 1

	st.parent.mu.RLock()
	defer st.parent.mu.RUnlock()

	llist := len(st.parent.list)
	if idx < 0 || idx >= llist {
		return "", nil, fmt.Errorf(`failed to encode to jwk.Key %T to PEM`, key)
	}

	st.current = idx

	e := st.parent.list[idx]
	return e.ASN1Encode(st.Next, key)
}

type NextASN1Encoder func(Key) (string, []byte, error)

// ASN1Encoder encodes a given key into ASN.1 format, so that it can be
// further encoded in PEM format.
type ASN1Encoder interface {
	// ASN1Encode takes a key, and returns three elements. The first string
	// is the name to be used when encoded in PEM format, the second
	// is the actual byte sequence encoded in ASN.1 format, and the
	// third is an error, if any.
	ASN1Encode(NextASN1Encoder, Key) (string, []byte, error)
}
type ASN1EncodeFunc func(NextASN1Encoder, Key) (string, []byte, error)

func (fn ASN1EncodeFunc) ASN1Encode(n NextASN1Encoder, key Key) (string, []byte, error) {
	return fn(n, key)
}

var chainedASN1E = &chainedASN1Encoder{
	list: []ASN1Encoder{ASN1EncodeFunc(asn1Encode)},
}

// AddASN1Encoder allows users
func AddASN1Encoder(enc ASN1Encoder) {
	chainedASN1E.Add(enc)
}

// Encodes a Key in DER ASN.1 format. Can handle RSA, EC, OKP keys.
func EncodeASN1(key Key) (string, []byte, error) {
	return chainedASN1E.Next(key)
}

func asn1Encode(_ NextASN1Encoder, key Key) (string, []byte, error) {
	switch key := key.(type) {
	case RSAPrivateKey, ECDSAPrivateKey, OKPPrivateKey:
		var rawkey interface{}
		if err := Raw(key, &rawkey); err != nil {
			return "", nil, fmt.Errorf(`failed to get raw key from jwk.Key: %w`, err)
		}
		buf, err := x509.MarshalPKCS8PrivateKey(rawkey)
		if err != nil {
			return "", nil, fmt.Errorf(`failed to marshal PKCS8: %w`, err)
		}
		return pmPrivateKey, buf, nil
	case RSAPublicKey, ECDSAPublicKey, OKPPublicKey:
		var rawkey interface{}
		if err := Raw(key, &rawkey); err != nil {
			return "", nil, fmt.Errorf(`failed to get raw key from jwk.Key: %w`, err)
		}
		buf, err := x509.MarshalPKIXPublicKey(rawkey)
		if err != nil {
			return "", nil, fmt.Errorf(`failed to marshal PKIX: %w`, err)
		}
		return pmPublicKey, buf, nil
	default:
		return "", nil, fmt.Errorf(`encoding key to ASN.1 failed: unsupported key type %T`, key)
	}
}

// Pem serializes the given jwk.Key in PEM encoded ASN.1 DER format,
// using either PKCS8 for private keys and PKIX for public keys.
// If you need to encode using PKCS1 or SEC1, you must do it yourself.
//
// # Argument must be of type jwk.Key or jwk.Set
//
// Currently only EC (including Ed25519) and RSA keys (and jwk.Set
// comprised of these key types) are supported.
func Pem(v interface{}) ([]byte, error) {
	var set Set
	switch v := v.(type) {
	case Key:
		set = NewSet()
		if err := set.AddKey(v); err != nil {
			return nil, fmt.Errorf(`failed to add key to set: %w`, err)
		}
	case Set:
		set = v
	default:
		return nil, fmt.Errorf(`argument to Pem must be either jwk.Key or jwk.Set: %T`, v)
	}

	var ret []byte
	for i := 0; i < set.Len(); i++ {
		key, _ := set.Key(i)
		typ, buf, err := chainedASN1E.Next(key)
		if err != nil {
			return nil, fmt.Errorf(`failed to encode content for key #%d: %w`, i, err)
		}

		var block pem.Block
		block.Type = typ
		block.Bytes = buf
		ret = append(ret, pem.EncodeToMemory(&block)...)
	}
	return ret, nil
}

// DecodePEM decodes a key in PEM encoded ASN.1 DER format.
// and returns a raw key
func DecodePEM(src []byte) (interface{}, []byte, error) {
	return chainedASN1D.Next(src)
}

func asn1Decode(_ ASN1Decoder, src []byte) (interface{}, []byte, error) {
	block, rest := pem.Decode(src)
	if block == nil {
		return nil, nil, fmt.Errorf(`failed to decode PEM data`)
	}

	switch block.Type {
	// Handle the semi-obvious cases
	case pmRSAPrivateKey:
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf(`failed to parse PKCS1 private key: %w`, err)
		}
		return key, rest, nil
	case pmRSAPublicKey:
		key, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf(`failed to parse PKCS1 public key: %w`, err)
		}
		return key, rest, nil
	case pmECPrivateKey:
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf(`failed to parse EC private key: %w`, err)
		}
		return key, rest, nil
	case pmPublicKey:
		// XXX *could* return dsa.PublicKey
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf(`failed to parse PKIX public key: %w`, err)
		}
		return key, rest, nil
	case pmPrivateKey:
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf(`failed to parse PKCS8 private key: %w`, err)
		}
		return key, rest, nil
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf(`failed to parse certificate: %w`, err)
		}
		return cert.PublicKey, rest, nil
	default:
		return nil, nil, fmt.Errorf(`invalid PEM block type %s`, block.Type)
	}
}

// EncodePEM encodes the key into a PEM encoded ASN.1 DER format.
// The key can be a jwk.Key or a raw key instance, but it must be one of
// the types supported by `x509` package.
//
// Internally, it uses the same routine as `jwk.EncodeX509()`, and therefore
// the same caveats apply
func EncodePEM(v interface{}) ([]byte, error) {
	typ, marshaled, err := EncodeX509(v)
	if err != nil {
		return nil, fmt.Errorf(`failed to encode key in x509: %w`, err)
	}

	block := &pem.Block{
		Type:  typ,
		Bytes: marshaled,
	}
	return pem.EncodeToMemory(block), nil
}
