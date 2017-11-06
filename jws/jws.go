// Package jws implements the digital signature on JSON based data
// structures as described in https://tools.ietf.org/html/rfc7515
//
// If you do not care about the details, the only things that you
// would need to use are the following functions:
//
//     jws.Sign(payload, algorithm, key)
//     jws.Verify(encodedjws, algorithm, key)
//
// To sign, simply use `jws.Sign`. `payload` is a []byte buffer that
// contains whatever data you want to sign. `alg` is one of the
// jwa.SignatureAlgorithm constants from package jwa. For RSA and
// ECDSA family of algorithms, you will need to prepare a private key.
// For HMAC family, you just need a []byte value. The `jws.Sign`
// function will return the encoded JWS message on success.
//
// To verify, use `jws.Verify`. It will parse the `encodedjws` buffer
// and verify the result using `algorithm` and `key`. Upon successful
// verification, the original payload is returned, so you can work on it.
package jws

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"

	"github.com/pkg/errors"
	"github.com/lestrrat/go-jwx/buffer"
	"github.com/lestrrat/go-jwx/internal/debug"
	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jwk"
)

// Sign is a short way to generate a JWS in compact serialization
// for a given payload. If you need more control over the signature
// generation process, you should manually create signers and tweak
// the message.
//
//
func Sign(payload []byte, alg jwa.SignatureAlgorithm, key interface{}, hdrs ...*Header) ([]byte, error) {
	var err error
	var signer PayloadSigner
	switch alg {
	case jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512:
		privkey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("invalid private key: *rsa.PrivateKey required")
		}

		signer, err = NewRsaSign(alg, privkey)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create RSA signer")
		}
	case jwa.HS256, jwa.HS384, jwa.HS512:
		sharedkey, ok := key.([]byte)
		if !ok {
			return nil, errors.New("invalid private key: []byte required")
		}

		signer, err = NewHmacSign(alg, sharedkey)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create HMAC signer")
		}
	case jwa.ES256, jwa.ES384, jwa.ES512:
		privkey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("invalid private key: *ecdsa.PrivateKey required")
		}

		signer, err = NewEcdsaSign(alg, privkey)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create ECDSA signer")
		}
	default:
		return nil, errors.Wrap(ErrUnsupportedAlgorithm, "provided altorithm is unsupported for signing")
	}

	if len(hdrs) > 0 {
		if pubhdr := hdrs[0]; pubhdr != nil {
			h, err := signer.PublicHeaders().Merge(pubhdr)
			if err != nil {
				return nil, errors.Wrap(err, `failed to merge public headers`)
			}
			signer.SetPublicHeaders(h)
		}
	}

	if len(hdrs) > 1 {
		if protectedhdr := hdrs[0]; protectedhdr != nil {
			h, err := signer.ProtectedHeaders().Merge(protectedhdr)
			if err != nil {
				return nil, errors.Wrap(err, "failed to merge protected headers")
			}
			signer.SetProtectedHeaders(h)
		}
	}

	multisigner := NewMultiSign()
	multisigner.AddSigner(signer)
	msg, err := multisigner.Sign(payload)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign payload")
	}

	return CompactSerialize{}.Serialize(msg)
}

// Verify checks if the given JWS message is verifiable using `alg` and `key`.
// If the verification is successful, `err` is nil, and the content of the
// payload that was signed is returned. If you need more fine-grained
// control of the verification process, manually call `Parse`, generate a
// verifier, and call `Verify` on the parsed JWS message object.
func Verify(buf []byte, alg jwa.SignatureAlgorithm, key interface{}) ([]byte, error) {
	if debug.Enabled {
		debug.Printf("jws.Verify\n")
	}
	msg, err := Parse(buf)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse buffer")
	}

	var verifier Verifier
	switch alg {
	case jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512:
		pubkey, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("invalid key: *rsa.PublicKey required")
		}

		rsaverify, err := NewRsaVerify(alg, pubkey)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create RSA signer")
		}
		verifier = rsaverify
	case jwa.HS256, jwa.HS384, jwa.HS512:
		sharedkey, ok := key.([]byte)
		if !ok {
			return nil, errors.New("invalid key: []byte required")
		}

		hmacverify, err := NewHmacVerify(alg, sharedkey)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create HMAC signer")
		}
		verifier = hmacverify
	case jwa.ES256, jwa.ES384, jwa.ES512:
		pubkey, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("invalid key: *ecdsa.PublicKey required")
		}

		ecdsaverify, err := NewEcdsaVerify(alg, pubkey)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create ECDSA signer")
		}
		verifier = ecdsaverify
	default:
		return nil, errors.Wrap(ErrUnsupportedAlgorithm, "provided altorithm is unsupported for verification")
	}

	if err := verifier.Verify(msg); err != nil {
		return nil, errors.Wrap(err, `verification failed`)
	}

	return msg.Payload.Bytes(), nil
}

// VerifyWithJKU verifies the JWS message using a remote JWK
// file represented in the url.
func VerifyWithJKU(buf []byte, jwkurl string) ([]byte, error) {
	key, err := jwk.FetchHTTP(jwkurl)
	if err != nil {
		return nil, errors.Wrap(err, `failed to fetch jwk via HTTP`)
	}

	return VerifyWithJWKSet(buf, key, nil)
}

var errVerifyFailed = errors.New("failed to verify with key")

func verifyMessageWithJWK(m *Message, key jwk.Key) error {
	keyval, err := key.Materialize()
	if err != nil {
		return errors.Wrap(err, `failed to materialize jwk.KEy`)
	}

	alg := jwa.SignatureAlgorithm(key.Alg())

	var verifier Verifier
	switch key.Kty() {
	case jwa.RSA:
		pubkey, ok := keyval.(*rsa.PublicKey)
		if !ok {
			return errors.New("invalid key: *rsa.PublicKey is required")
		}
		verifier, err = NewRsaVerify(alg, pubkey)
		if err != nil {
			return errors.Wrap(err, "failed to create RSA verifier")
		}
	case jwa.EC:
		pubkey, ok := keyval.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("invalid key: *ecdsa.PublicKey is required")
		}
		verifier, err = NewEcdsaVerify(alg, pubkey)
		if err != nil {
			return errors.Wrap(err, "failed to create ECDSA verifier")
		}
	case jwa.OctetSeq:
		sharedkey, ok := keyval.([]byte)
		if !ok {
			return errors.New("invalid key: []byte is required")
		}
		verifier, err = NewHmacVerify(alg, sharedkey)
		if err != nil {
			return errors.Wrap(err, "failed to create HMAC verifier")
		}
	default:
		// don't know what this is...
		return errors.New("unknown signature algorithm")
	}

	if err := verifier.Verify(m); err != nil {
		// we return a stock "failed to verify" error so callers
		// can differentiate between other errors and Verify() failing
		// note: this masks potential errors within Verify(), but ... hmmm
		return errVerifyFailed
	}

	return nil
}

// VerifyWithJWK verifies the JWS message using the specified JWK
func VerifyWithJWK(buf []byte, key jwk.Key) ([]byte, error) {
	m, err := Parse(buf)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse buffer")
	}

	if err := verifyMessageWithJWK(m, key); err != nil {
		return nil, errors.Wrap(err, "failed to verify message")
	}
	return m.Payload.Bytes(), nil
}

// VerifyWithJWKSet verifies the JWS message using JWK key set.
// By default it will only pick up keys that have the "use" key
// set to either "sig" or "enc", but you can override it by
// providing a keyaccept function.
func VerifyWithJWKSet(buf []byte, keyset *jwk.Set, keyaccept JWKAcceptFunc) ([]byte, error) {
	m, err := Parse(buf)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse buffer")
	}

	if keyaccept == nil {
		keyaccept = DefaultJWKAcceptor
	}

	for _, key := range keyset.Keys {
		if !keyaccept(key) {
			continue
		}

		switch err := verifyMessageWithJWK(m, key); err {
		case nil:
			return m.Payload.Bytes(), nil
		case errVerifyFailed:
			continue
		default:
			return nil, errors.Wrap(err, "unrecoverable error while verifying")
		}
	}

	return nil, errors.New("failed to verify with any of the keys")
}

// Parse parses the given buffer and creates a jws.Message struct.
// The input can be in either compact or full JSON serialization.
func Parse(buf []byte) (*Message, error) {
	buf = bytes.TrimSpace(buf)
	if len(buf) == 0 {
		return nil, errors.New("empty buffer")
	}

	if buf[0] == '{' {
		return parseJSON(buf)
	}
	return parseCompact(buf)
}

// ParseString is the same as Parse, but take in a string
func ParseString(s string) (*Message, error) {
	return Parse([]byte(s))
}

func parseJSON(buf []byte) (*Message, error) {
	m := struct {
		*Message
		*Signature
	}{}

	if err := json.Unmarshal(buf, &m); err != nil {
		return nil, errors.Wrap(err, `failed to parse jwk.Message`)
	}

	// if the "signature" field exist, treat it as a flattened
	if m.Signature != nil {
		if len(m.Message.Signatures) != 0 {
			return nil, errors.New("invalid message: mixed flattened/full json serialization")
		}

		m.Message.Signatures = []Signature{*m.Signature}
	}

	for _, sig := range m.Message.Signatures {
		if sig.ProtectedHeader.Algorithm == "" {
			sig.ProtectedHeader.Algorithm = jwa.NoSignature
		}
	}

	return m.Message, nil
}

// parseCompact parses a JWS value serialized via compact serialization.
func parseCompact(buf []byte) (*Message, error) {
	parts := bytes.Split(buf, []byte{'.'})
	if len(parts) != 3 {
		return nil, ErrInvalidCompactPartsCount
	}

	enc := base64.RawURLEncoding

	hdrbuf, err := buffer.FromBase64(parts[0])
	if err != nil {
		return nil, errors.Wrap(err, `failed to parse first part from base64`)
	}

	hdr := &EncodedHeader{Header: NewHeader()}
	if err := json.Unmarshal(hdrbuf.Bytes(), hdr.Header); err != nil {
		return nil, errors.Wrap(err, `failed to parse header from JSON`)
	}
	hdr.Source = hdrbuf

	payload, err := buffer.FromBase64(parts[1])
	if err != nil {
		return nil, errors.Wrap(err, `failed to parse second part from base64`)
	}

	signature := make([]byte, enc.DecodedLen(len(parts[2])))
	if _, err := enc.Decode(signature, parts[2]); err != nil {
		return nil, errors.Wrap(err, `failed to decode third part`)
	}

	s := NewSignature()
	s.Signature = signature
	s.ProtectedHeader = hdr
	m := &Message{
		Payload:    buffer.Buffer(payload),
		Signatures: []Signature{*s},
	}
	return m, nil
}
