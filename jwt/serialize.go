package jwt

import (
	"fmt"

	"github.com/lestrrat-go/jwx/internal/json"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/pkg/errors"
)

type SerializeStep interface {
	Do(interface{}) (interface{}, error)
}

// Serializer is a generic serializer for JWTs. Whereas other conveinience
// functions can only do one thing (such as generate a JWS signed JWT),
// Using this construct you can serialize the token however you want.
//
// By default the serializer does not do anything. You must set up
// each of the steps that the serializer converts the data.
// For example, to marshal the token into JSON, then apply JWS and JWE
// in that order, you would do:
//
//   serialized, err := jwt.NewSerialer().
//      JSON().
//      Sign(jwa.RS256, key).
//      Encrypt(jwa.RSA_OAEP, key.PublicKey).
//      Do(token)
type Serializer struct {
	steps []SerializeStep
}

func NewSerializer() *Serializer {
	return &Serializer{}
}

type jsonSerializer struct{}

func (jsonSerializer) Do(v interface{}) (interface{}, error) {
	buf, err := json.Marshal(v)
	if err != nil {
		return nil, errors.Errorf(`failed to serialize as JSON`)
	}
	return buf, nil
}

func (s *Serializer) JSON() *Serializer {
	s.steps = append(s.steps, &jsonSerializer{})
	return s
}

type jwsSerializer struct {
	alg jwa.SignatureAlgorithm
	key interface{}
}

func (s *jwsSerializer) Do(v interface{}) (interface{}, error) {
	payload, ok := v.([]byte)
	if !ok {
		return nil, errors.New(`expected []byte as input`)
	}

	hdrs := jws.NewHeaders()
	if err := hdrs.Set(jws.ContentTypeKey, `JWT`); err != nil {
		return nil, errors.Wrapf(err, `failed to set %s key to "JWT"`, jws.ContentTypeKey)
	}
	return jws.Sign(payload, s.alg, s.key, jws.WithHeaders(hdrs))
}

func (s *Serializer) Sign(alg jwa.SignatureAlgorithm, key interface{}) *Serializer {
	s.steps = append(s.steps, &jwsSerializer{
		alg: alg,
		key: key,
	})
	return s
}

type jweSerializer struct {
	keyalg      jwa.KeyEncryptionAlgorithm
	key         interface{}
	contentalg  jwa.ContentEncryptionAlgorithm
	compressalg jwa.CompressionAlgorithm
}

func (s *jweSerializer) Do(v interface{}) (interface{}, error) {
	payload, ok := v.([]byte)
	if !ok {
		return nil, fmt.Errorf(`expected []byte as input`)
	}

	hdrs := jwe.NewHeaders()
	if err := hdrs.Set(jwe.ContentTypeKey, `JWT`); err != nil {
		return nil, errors.Wrapf(err, `failed to set %s key to "JWT"`, jwe.ContentTypeKey)
	}
	return jwe.Encrypt(payload, s.keyalg, s.key, s.contentalg, s.compressalg, jwe.WithProtectedHeaders(hdrs))
}

func (s *Serializer) Encrypt(keyalg jwa.KeyEncryptionAlgorithm, key interface{}, contentalg jwa.ContentEncryptionAlgorithm, compressalg jwa.CompressionAlgorithm) *Serializer {
	s.steps = append(s.steps, &jweSerializer{
		keyalg:      keyalg,
		key:         key,
		contentalg:  contentalg,
		compressalg: compressalg,
	})
	return s
}

func (s *Serializer) Do(t Token) ([]byte, error) {
	if len(s.steps) == 0 {
		return nil, errors.New(`serializer setup incomplete: you must add steps to it`)
	}

	var payload interface{} = t
	for i, step := range s.steps {
		v, err := step.Do(payload)
		if err != nil {
			return nil, errors.Wrapf(err, `failed to serialize token at step #%d`, i+1)
		}
		payload = v
	}

	res, ok := payload.([]byte)
	if !ok {
		return nil, errors.New(`invalid serialization produced`)
	}

	return res, nil
}
