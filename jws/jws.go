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
	"errors"

	"github.com/lestrrat/go-jwx/buffer"
	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jwk"
)

// Sign is a short way to generate a JWS in compact serialization
// for a given payload. If you need more control over the signature
// generation process, you should manually create signers and tweak
// the message.
func Sign(payload []byte, alg jwa.SignatureAlgorithm, key interface{}) ([]byte, error) {
	signer := NewMultiSign()
	switch alg {
	case jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512:
		privkey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("invalid private key: *rsa.PrivateKey required")
		}

		rsasign, err := NewRsaSign(alg, privkey)
		if err != nil {
			return nil, err
		}
		signer.AddSigner(rsasign)
	case jwa.HS256, jwa.HS384, jwa.HS512:
		sharedkey, ok := key.([]byte)
		if !ok {
			return nil, errors.New("invalid private key: []byte required")
		}

		hmacsign, err := NewHmacSign(alg, sharedkey)
		if err != nil {
			return nil, err
		}
		signer.AddSigner(hmacsign)
	case jwa.ES256, jwa.ES384, jwa.ES512:
		privkey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("invalid private key: *ecdsa.PrivateKey required")
		}

		ecdsasign, err := NewEcdsaSign(alg, privkey)
		if err != nil {
			return nil, err
		}
		signer.AddSigner(ecdsasign)
	default:
		return nil, ErrUnsupportedAlgorithm
	}

	msg, err := signer.Sign(payload)
	if err != nil {
		return nil, err
	}

	return CompactSerialize{}.Serialize(msg)
}

// Verify checks if the given JWS message is verifiable using `alg` and `key`.
// If the verification is successful, `err` is nil, and the content of the
// payload that was signed is returned. If you need more fine-grained
// control of the verification process, manually call `Parse`, generate a
// verifier, and call `Verify` on the parsed JWS message object.
func Verify(buf []byte, alg jwa.SignatureAlgorithm, key interface{}) ([]byte, error) {
	msg, err := Parse(buf)
	if err != nil {
		return nil, err
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
			return nil, err
		}
		verifier = rsaverify
	case jwa.HS256, jwa.HS384, jwa.HS512:
		sharedkey, ok := key.([]byte)
		if !ok {
			return nil, errors.New("invalid key: []byte required")
		}

		hmacverify, err := NewHmacVerify(alg, sharedkey)
		if err != nil {
			return nil, err
		}
		verifier = hmacverify
	case jwa.ES256, jwa.ES384, jwa.ES512:
		pubkey, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("invalid key: *ecdsa.PublicKey required")
		}

		ecdsaverify, err := NewEcdsaVerify(alg, pubkey)
		if err != nil {
			return nil, err
		}
		verifier = ecdsaverify
	default:
		return nil, ErrUnsupportedAlgorithm
	}

	if err := verifier.Verify(msg); err != nil {
		return nil, err
	}
	return msg.Payload.Bytes(), nil
}

func VerifyWithJWK(buf []byte, keyset jwk.Set) ([]byte, error) {
	m, err := Parse(buf)
	if err != nil {
		return nil, err
	}

	for _, key := range keyset.Keys {
		if u := key.Use(); u != "" && u != "enc" {
			continue
		}

		keyval, err := key.Materialize()
		if err != nil {
			return nil, err
		}

		alg := jwa.SignatureAlgorithm(key.Alg())

		var verifier Verifier
		switch key.Kty() {
		case jwa.RSA:
			pubkey, ok := keyval.(*rsa.PublicKey)
			if !ok {
				return nil, errors.New("invalid key: *rsa.PublicKey is required")
			}
			verifier, err = NewRsaVerify(alg, pubkey)
			if err != nil {
				return nil, err
			}
		case jwa.EC:
			pubkey, ok := keyval.(*ecdsa.PublicKey)
			if !ok {
				return nil, errors.New("invalid key: *ecdsa.PublicKey is required")
			}
			verifier, err = NewEcdsaVerify(alg, pubkey)
			if err != nil {
				return nil, err
			}
		case jwa.OctetSeq:
			sharedkey, ok := keyval.([]byte)
			if !ok {
				return nil, errors.New("invalid key: []byte is required")
			}
			verifier, err = NewHmacVerify(alg, sharedkey)
			if err != nil {
				return nil, err
			}
		default:
			continue
		}

		if err := verifier.Verify(m); err != nil {
			continue
		}

		return m.Payload.Bytes(), nil
	}

	return nil, errors.New("failed to verify")
}

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

func ParseString(s string) (*Message, error) {
	return Parse([]byte(s))
}

func parseJSON(buf []byte) (*Message, error) {
	m := struct {
		*Message
		*Signature
	}{}

	if err := json.Unmarshal(buf, &m); err != nil {
		return nil, err
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
		return nil, err
	}

	hdr := &EncodedHeader{Header: NewHeader()}
	if err := json.Unmarshal(hdrbuf.Bytes(), hdr.Header); err != nil {
		return nil, err
	}
	hdr.Source = hdrbuf

	payload, err := buffer.FromBase64(parts[1])
	if err != nil {
		return nil, err
	}

	signature := make([]byte, enc.DecodedLen(len(parts[2])))
	if _, err := enc.Decode(signature, parts[2]); err != nil {
		return nil, err
	}
	signature = bytes.TrimRight(signature, "\x00")

	s := NewSignature()
	s.Signature = signature
	s.ProtectedHeader = hdr
	m := &Message{
		Payload:    buffer.Buffer(payload),
		Signatures: []Signature{*s},
	}
	return m, nil
}
