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
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"unicode"

	"github.com/lestrrat/go-jwx/buffer"
	"github.com/lestrrat/go-jwx/internal/debug"
	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jwk"
	"github.com/pkg/errors"
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
	msg, err := Parse(bytes.NewReader(buf))
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
	m, err := Parse(bytes.NewReader(buf))
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
	m, err := Parse(bytes.NewReader(buf))
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

// Parse parses contents from the given source and creates a jws.Message
// struct. The input can be in either compact or full JSON serialization.
func Parse(src io.Reader) (*Message, error) {
	rdr := bufio.NewReader(src)
	var first rune
	for {
		r, _, err := rdr.ReadRune()
		if err != nil {
			return nil, errors.Wrap(err, `failed to read rune`)
		}
		if !unicode.IsSpace(r) {
			first = r
			rdr.UnreadRune()
			break
		}
	}

	if first == '{' {
		return parseJSON(rdr)
	}
	return parseCompact(rdr)
}

// ParseString is the same as Parse, but take in a string
func ParseString(s string) (*Message, error) {
	return Parse(strings.NewReader(s))
}

func parseJSON(src io.Reader) (*Message, error) {
	m := struct {
		*Message
		*Signature
	}{}

	if err := json.NewDecoder(src).Decode(&m); err != nil {
		return nil, errors.Wrap(err, `failed to parse jws message`)
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

func scanDot(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}

	if i := bytes.IndexByte(data, '.'); i >= 0 {
		return i + 1, data[0:i], nil
	}

	// If we're at EOF, we have a final, non-terminated line. Return it.
	if atEOF {
		return len(data), data, nil
	}
	// Request more data.
	return 0, nil, nil
}

// parseCompact parses a JWS value serialized via compact serialization.
func parseCompact(rdr io.Reader) (*Message, error) {
	var hdr = &EncodedHeader{Header: NewHeader()}
	var payload []byte
	var signbuf []byte
	var periods int
	var state int

	buf := make([]byte, 4096)
	var sofar []byte
	for {
		n, err := rdr.Read(buf)
		if n == 0 && err != nil {
			break
		}
		sofar = append(sofar, buf[:n]...)
		for loop := true; loop; {
			i := bytes.IndexByte(sofar, '.')
			switch i {
			case -1:
				l := len(sofar)
				if l <= 0 {
					loop = false
					continue
				}
				i = l
			default:
				periods++
			}

			switch state {
			case 0:
				hdrbuf, err := buffer.FromBase64(sofar[:i])
				if err != nil {
					return nil, errors.Wrap(err, `failed to decode headers`)
				}
				if err := json.Unmarshal(hdrbuf, hdr.Header); err != nil {
					return nil, errors.Wrap(err, `failed to parse JOSE headers`)
				}
				hdr.Source = hdrbuf
				state++
			case 1:
				payload, err = buffer.FromBase64(sofar[:i])
				if err != nil {
					return nil, errors.Wrap(err, `failed to decode payload`)
				}
				state++
			case 2:
				signbuf = make([]byte, base64.RawURLEncoding.DecodedLen(i))
				if _, err := base64.RawURLEncoding.Decode(signbuf, sofar[:i]); err != nil {
					return nil, errors.Wrap(err, `failed to decode signature`)
				}
			}
			if len(sofar) <= i {
				sofar = []byte(nil)
			} else {
				sofar = sofar[i+1:]
			}
		}

	}
	if periods != 2 {
		return nil, errors.New(`invalid number of segments`)
	}

	s := NewSignature()
	s.Signature = signbuf
	s.ProtectedHeader = hdr
	m := &Message{
		Payload:    buffer.Buffer(payload),
		Signatures: []Signature{*s},
	}
	return m, nil
}
