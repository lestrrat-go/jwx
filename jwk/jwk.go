// Package jwk implements JWK as described in https://tools.ietf.org/html/rfc7517
package jwk

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"

	"github.com/lestrrat/go-jwx/internal/emap"
	"github.com/lestrrat/go-jwx/jwa"
	"github.com/pkg/errors"
)

// FetchFile fetches the local JWK from file, and parses its contents
func FetchFile(jwkpath string) (*Set, error) {
	f, err := os.Open(jwkpath)
	if err != nil {
		return nil, errors.Wrap(err, `failed to open jwk file`)
	}
	defer f.Close()

	buf, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, errors.Wrap(err, `failed read content from jwk file`)
	}

	return Parse(buf)
}

// FetchHTTP fetches the remote JWK and parses its contents
func FetchHTTP(jwkurl string) (*Set, error) {
	res, err := http.Get(jwkurl)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch remote JWK")
	}

	if res.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch remote JWK (status != 200)")
	}

	// XXX Check for maximum length to read?
	buf, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read JWK HTTP response body")
	}
	defer res.Body.Close()

	return Parse(buf)
}

// Parse parses JWK from the incoming byte buffer.
func Parse(buf []byte) (*Set, error) {
	m := make(map[string]interface{})
	if err := json.Unmarshal(buf, &m); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal JWK")
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
		return nil, errors.Wrap(err, `failed to construct key from keys`)
	}
	return &Set{Keys: []Key{k}}, nil
}

// ParseString parses JWK from the incoming string.
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
		return nil, errors.Wrap(err, "failed to find 'kty' key from JWK headers")
	}
	e.KeyType = jwa.KeyType(kty)

	// https://tools.ietf.org/html/rfc7517#section-4.2
	e.KeyUsage, _ = r.GetString("use")

	// https://tools.ietf.org/html/rfc7517#section-4.3
	if v, err := r.GetStringSlice("key_ops"); err == nil {
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
			return nil, errors.Wrap(err, "failed to parse 'x5u' key")
		}
		e.X509Url = u
	}

	// https://tools.ietf.org/html/rfc7517#section-4.7
	if v, err := r.GetStringSlice("x5c"); err == nil {
		e.X509CertChain = v
	}

	return e, nil
}

func constructSymmetricKey(m map[string]interface{}) (*SymmetricKey, error) {
	r := emap.Hmap(m)

	h, err := constructEssentialHeader(m)
	if err != nil {
		return nil, errors.Wrap(err, `failed to construct essential header`)
	}

	key := &SymmetricKey{EssentialHeader: h}

	k, err := r.GetBuffer("k")
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch 'k' field for symmetric key")
	}
	key.Key = k

	return key, nil
}

func constructEcdsaPublicKey(m map[string]interface{}) (*EcdsaPublicKey, error) {
	e, err := constructEssentialHeader(m)
	if err != nil {
		return nil, errors.Wrap(err, "failed to construct essential headers for ECDSA public key")
	}
	r := emap.Hmap(m)

	crvstr, err := r.GetString("crv")
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch 'crv' key for ECDSA public key")
	}
	crv := jwa.EllipticCurveAlgorithm(crvstr)

	x, err := r.GetBuffer("x")
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch 'x' key for ECDSA public key")
	}

	if x.Len() != crv.Size() {
		return nil, errors.New("size of x does not match crv size for ECDSA public key")
	}

	y, err := r.GetBuffer("y")
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch 'y' key for ECDSA public key")
	}

	if y.Len() != crv.Size() {
		return nil, errors.New("size of y does not match crv size for ECDSA public key")
	}

	return &EcdsaPublicKey{
		EssentialHeader: e,
		Curve:           jwa.EllipticCurveAlgorithm(crv),
		X:               x,
		Y:               y,
	}, nil
}

func constructEcdsaPrivateKey(m map[string]interface{}) (*EcdsaPrivateKey, error) {
	pubkey, err := constructEcdsaPublicKey(m)
	if err != nil {
		return nil, errors.Wrap(err, "failed to construct essential header for ECDSA private key")
	}

	r := emap.Hmap(m)
	d, err := r.GetBuffer("d")
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch 'd' key for ECDSA private key")
	}

	return &EcdsaPrivateKey{
		EcdsaPublicKey: pubkey,
		D:              d,
	}, nil
}

func constructRsaPublicKey(m map[string]interface{}) (*RsaPublicKey, error) {
	e, err := constructEssentialHeader(m)
	if err != nil {
		return nil, errors.Wrap(err, "failed to construct essential header for RSA public key")
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
		return nil, errors.Wrap(err, `failed to construct RSA publick key`)
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

// Alg returns the algorithm in the header
func (e EssentialHeader) Alg() string {
	return e.Algorithm
}

// Kid returns the key ID in the header
func (e EssentialHeader) Kid() string {
	return e.KeyID
}

// Kty returns the key type in the header
func (e EssentialHeader) Kty() jwa.KeyType {
	return e.KeyType
}

// Use returns the key use in the header
func (e EssentialHeader) Use() string {
	return e.KeyUsage
}
