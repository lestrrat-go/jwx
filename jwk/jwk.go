// Package jwk implements JWK as described in https://tools.ietf.org/html/rfc7517
package jwk

import (
	"encoding/json"
	"errors"
	"net/url"
	"reflect"

	"github.com/lestrrat/go-jwx/internal/emap"
	"github.com/lestrrat/go-jwx/jwa"
)

// Parse parses JWK in JSON format from the incoming `io.Reader`.
// If you are expecting that you *might* get a KeySet, you should
// fallback to using ParseKeySet
func Parse(buf []byte) (*Set, error) {
	m := make(map[string]interface{})
	if err := json.Unmarshal(buf, &m); err != nil {
		return nil, err
	}

	// We must change what the underlying structure that gets decoded
	// out of this JSON is based on parameters within the already parsed
	// JSON (m). In order to do this, we have to go through the tedious
	// task of parsing the contents of this map :/
	if _, ok := m["keys"]; ok {
		return constructSet(m)
	}
	k, err := constructKey(m)
	if err != nil {
		return nil, err
	}
	return &Set{Keys: []Key{k}}, nil
}

func ParseString(s string) (*Set, error) {
	return Parse([]byte(s))
}

func constructKey(m map[string]interface{}) (Key, error) {
	kty, ok := m["kty"].(string)
	if !ok {
		return nil, ErrUnsupportedKty
	}

	switch jwa.KeyType(kty) {
	case jwa.RSA:
		if _, ok := m["d"]; ok {
			return constructRsaPrivateKey(m)
		}
		return constructRsaPublicKey(m)
	case jwa.EC:
		if _, ok := m["d"]; ok {
			return constructEcdsaPrivateKey(m)
		}
		return constructEcdsaPublicKey(m)
	case jwa.OctetSeq:
		return constructSymmetricKey(m)
	default:
		return nil, ErrUnsupportedKty
	}
}

func constructEssentialHeader(m map[string]interface{}) (*EssentialHeader, error) {
	r := emap.Hmap(m)
	e := &EssentialHeader{}

	// https://tools.ietf.org/html/rfc7517#section-4.1
	kty, err := r.GetString("kty")
	if err != nil {
		return nil, err
	}
	e.KeyType = jwa.KeyType(kty)

	// https://tools.ietf.org/html/rfc7517#section-4.2
	e.KeyUsage, _ = r.GetString("use")

	// https://tools.ietf.org/html/rfc7517#section-4.3
	if v, err := r.GetStringSlice("key_ops"); err != nil {
		if len(v) > 0 {
			e.KeyOps = make([]KeyOperation, len(v))
			for i, x := range v {
				e.KeyOps[i] = KeyOperation(x)
			}
		}
	}

	// https://tools.ietf.org/html/rfc7517#section-4.4
	e.Algorithm, _ = r.GetString("alg")

	// https://tools.ietf.org/html/rfc7517#section-4.5
	e.KeyID, _ = r.GetString("kid")

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

func constructSymmetricKey(m map[string]interface{}) (*SymmetricKey, error) {
	r := emap.Hmap(m)

	h, err := constructEssentialHeader(m)
	if err != nil {
		return nil, err
	}

	key := &SymmetricKey{EssentialHeader: h}

	k, err := r.GetBuffer("k")
	if err != nil {
		return nil, err
	}
	key.Key = k

	return key, nil
}

func constructEcdsaPublicKey(m map[string]interface{}) (*EcdsaPublicKey, error) {
	e, err := constructEssentialHeader(m)
	if err != nil {
		return nil, err
	}
	r := emap.Hmap(m)

	crvstr, err := r.GetString("crv")
	if err != nil {
		return nil, err
	}
	crv := jwa.EllipticCurveAlgorithm(crvstr)

	x, err := r.GetBuffer("x")
	if err != nil {
		return nil, err
	}

	if x.Len() != crv.Size() {
		return nil, errors.New("size of x does not match crv size")
	}

	y, err := r.GetBuffer("y")
	if err != nil {
		return nil, err
	}

	if y.Len() != crv.Size() {
		return nil, errors.New("size of y does not match crv size")
	}

	return &EcdsaPublicKey{
		EssentialHeader: e,
		Curve: jwa.EllipticCurveAlgorithm(crv),
		X: x,
		Y: y,
	}, nil
}

func constructEcdsaPrivateKey(m map[string]interface{}) (*EcdsaPrivateKey, error) {
	pubkey, err := constructEcdsaPublicKey(m)
	if err != nil {
		return nil, err
	}

	r := emap.Hmap(m)
	d, err := r.GetBuffer("d")
	if err != nil {
		return nil, err
	}

	return &EcdsaPrivateKey{
		EcdsaPublicKey: pubkey,
		D: d,
	}, nil
}

func constructRsaPublicKey(m map[string]interface{}) (*RsaPublicKey, error) {
	e, err := constructEssentialHeader(m)
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

	k := &RsaPublicKey{EssentialHeader: e}

	r := emap.Hmap(m)
	if v, err := r.GetBuffer("e"); err == nil {
		k.E = v
	}

	if v, err := r.GetBuffer("n"); err == nil {
		k.N = v
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
	if v, err := r.GetBuffer("d"); err == nil {
		k.D = v
	}

	if v, err := r.GetBuffer("p"); err == nil {
		k.P = v
	}

	if v, err := r.GetBuffer("q"); err == nil {
		k.Q = v
	}

	if v, err := r.GetBuffer("dp"); err == nil {
		k.Dp = v
	}

	if v, err := r.GetBuffer("dq"); err == nil {
		k.Dq = v
	}

	if v, err := r.GetBuffer("qi"); err == nil {
		k.Qi = v
	}

	return k, nil
}

func (e EssentialHeader) Alg() string {
	return e.Algorithm
}

func (e EssentialHeader) Kid() string {
	return e.KeyID
}

func (e EssentialHeader) Kty() jwa.KeyType {
	return e.KeyType
}

func (e EssentialHeader) Use() string {
	return e.KeyUsage
}
