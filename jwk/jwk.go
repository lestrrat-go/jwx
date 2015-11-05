package jwk

import (
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"reflect"

	"github.com/lestrrat/go-jwx/buffer"
	"github.com/lestrrat/go-jwx/emap"
)

// Parse parses JWK in JSON format from the incoming `io.Reader`.
// If you are expecting that you *might* get a KeySet, you should
// fallback to using ParseKeySet
func Parse(rdr io.Reader) (JsonWebKey, error) {
	m := make(map[string]interface{})
	if err := json.NewDecoder(rdr).Decode(&m); err != nil {
		return nil, err
	}

	// We must change what the underlying structure that gets decoded
	// out of this JSON is based on parameters within the already parsed
	// JSON (m). In order to do this, we have to go through the tedious
	// task of parsing the contents of this map :/
	return constructKey(m)
}

func constructKey(m map[string]interface{}) (JsonWebKey, error) {
	switch m["kty"] {
	case "RSA":
		if _, ok := m["d"]; ok {
			return constructRsaPrivateKey(m)
		}
		return constructRsaPublicKey(m)
	default:
		return nil, errors.New("unsupported kty")
	}
}

func constructEssential(m map[string]interface{}) (*Essential, error) {
	r := emap.Hmap(m)
	e := &Essential{}

	var err error
	// https://tools.ietf.org/html/rfc7517#section-4.1
	if e.KeyType, err = r.GetString("kty"); err != nil {
		return nil, err
	}

	// https://tools.ietf.org/html/rfc7517#section-4.2
	e.Use, _ = r.GetString("use")

	// https://tools.ietf.org/html/rfc7517#section-4.3
	if v, err := r.Get("key_ops", reflect.TypeOf(e.KeyOps)); err == nil {
		e.KeyOps = v.([]string)
	}

	// https://tools.ietf.org/html/rfc7517#section-4.4
	e.Algorithm, _ = r.GetString("alg")

	// https://tools.ietf.org/html/rfc7517#section-4.5
	e.KeyId, _ = r.GetString("kid")

	// https://tools.ietf.org/html/rfc7517#section-4.6
	if v, err := r.GetString("x5u"); err == nil {
		u, err := url.Parse(v)
		if err != nil {
			return nil, err
		}
		e.X509Url = u
	}

	// https://tools.ietf.org/html/rfc7517#section-4.7
	if v, err := r.Get("x5c", reflect.TypeOf(e.X509CertChain)); err == nil {
		e.X509CertChain = v.([]string)
	}

	return e, nil
}

func constructRsaPublicKey(m map[string]interface{}) (*RsaPublicKey, error) {
	e, err := constructEssential(m)
	if err != nil {
		return nil, err
	}

	for _, name := range []string{"n", "e"} {
		v, ok := m[name]
		if !ok {
			return nil, errors.New("missing parameter '" + name + "'")
		}
		if _, ok := v.(string); !ok {
			return nil, errors.New("missing parameter '" + name + "'")
		}
	}

	k := &RsaPublicKey{Essential: e}

	r := emap.Hmap(m)
	if v, err := r.GetByteSlice("e"); err == nil {
		k.E = buffer.Buffer(v)
	}

	if v, err := r.GetByteSlice("n"); err == nil {
		k.N = buffer.Buffer(v)
	}

	return k, nil
}

func constructRsaPrivateKey(m map[string]interface{}) (*RsaPrivateKey, error) {
	for _, name := range []string{"d", "q", "p"} {
		v, ok := m[name]
		if !ok {
			return nil, errors.New("missing parameter '" + name + "'")
		}
		if _, ok := v.(string); !ok {
			return nil, errors.New("missing parameter '" + name + "'")
		}
	}

	pubkey, err := constructRsaPublicKey(m)
	if err != nil {
		return nil, err
	}

	k := &RsaPrivateKey{RsaPublicKey: pubkey}

	r := emap.Hmap(m)
	if v, err := r.GetByteSlice("d"); err == nil {
		k.D = buffer.Buffer(v)
	}

	if v, err := r.GetByteSlice("p"); err == nil {
		k.P = buffer.Buffer(v)
	}

	if v, err := r.GetByteSlice("q"); err == nil {
		k.Q = buffer.Buffer(v)
	}

	return k, nil
}

func (e Essential) Kid() string {
	return e.KeyId
}

func (e Essential) Kty() string {
	return e.KeyType
}
