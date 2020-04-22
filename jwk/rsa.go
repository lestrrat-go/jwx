package jwk

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"encoding/binary"
	"math/big"

	"github.com/lestrrat-go/jwx/internal/base64"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/pkg/errors"
)

func newRSAPrivateKey(rawKey *rsa.PrivateKey) (*RSAPrivateKey, error) {
	var key RSAPrivateKey

	key.Set(KeyTypeKey, jwa.RSA)

	key.d = rawKey.D.Bytes()
	if len(rawKey.Primes) < 2 {
		return nil, errors.Errorf(`invalid number of primes in rsa.PrivateKey: need 2, got %d`, len(rawKey.Primes))
	}

	key.p = rawKey.Primes[0].Bytes()
	key.q = rawKey.Primes[1].Bytes()

	if v := rawKey.Precomputed.Dp; v != nil {
		key.dp = v.Bytes()
	}
	if v := rawKey.Precomputed.Dq; v != nil {
		key.dq = v.Bytes()
	}
	if v := rawKey.Precomputed.Qinv; v != nil {
		key.qi = v.Bytes()
	}

	key.n = rawKey.PublicKey.N.Bytes()
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, uint64(rawKey.PublicKey.E))
	i := 0
	for ; i < len(data); i++ {
		if data[i] != 0x0 {
			break
		}
	}
	key.e = data[i:]

	return &key, nil
}

func newRSAPublicKey(rawKey *rsa.PublicKey) (*RSAPublicKey, error) {
	var key RSAPublicKey

	key.Set(KeyTypeKey, jwa.RSA)

	key.n = rawKey.N.Bytes()
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, uint64(rawKey.E))
	i := 0
	for ; i < len(data); i++ {
		if data[i] != 0x0 {
			break
		}
	}
	key.e = data[i:]

	return &key, nil
}

func (k *RSAPrivateKey) Materialize(v interface{}) error {
	var d, q, p big.Int
	d.SetBytes(k.d)
	q.SetBytes(k.q)
	p.SetBytes(k.p)

	// optional fields
	var dp, dq, qi *big.Int
	if len(k.dp) > 0 {
		dp = &big.Int{}
		dp.SetBytes(k.dp)
	}

	if len(k.dq) > 0 {
		dq = &big.Int{}
		dq.SetBytes(k.dq)
	}

	if len(k.qi) > 0 {
		qi = &big.Int{}
		qi.SetBytes(k.qi)
	}

	var key rsa.PrivateKey

	pubk := &RSAPublicKey{
		n: k.n,
		e: k.e,
	}
	if err := pubk.Materialize(&key.PublicKey); err != nil {
		return errors.Wrap(err, `failed to materialize RSA public key`)
	}

	key.D = &d
	key.Primes = []*big.Int{&p, &q}

	if dp != nil {
		key.Precomputed.Dp = dp
	}
	if dq != nil {
		key.Precomputed.Dq = dq
	}
	if qi != nil {
		key.Precomputed.Qinv = qi
	}

	return assignMaterializeResult(v, &key)
}

// Materialize takes the values stored in the Key object, and creates the
// corresponding *rsa.PublicKey object.
func (k *RSAPublicKey) Materialize(v interface{}) error {
	var key rsa.PublicKey

	var n, e big.Int
	n.SetBytes(k.n)
	e.SetBytes(k.e)

	key.N = &n
	key.E = int(e.Int64())

	return assignMaterializeResult(v, &key)
}

func (k RSAPrivateKey) PublicKey() (*RSAPublicKey, error) {
	var key rsa.PrivateKey
	if err := k.Materialize(&key); err != nil {
		return nil, errors.Wrap(err, `failed to materialize key to generate public key`)
	}
	return newRSAPublicKey(&key.PublicKey)
}

/*
func populateRSAHeaders(h Headers, key interface{}) {
	h.Set(KeyTypeKey, jwa.RSA)

	var pubk *rsa.PublicKey
	if privk, ok := key.(*rsa.PrivateKey); ok {
		pubk = &privk.PublicKey

		h.Set(rsaDKey, privk.D.Bytes())
		h.Set(rsaPKey, privk.Primes[0].Bytes())
		h.Set(rsaQKey, privk.Primes[1].Bytes())
		if v := privk.Precomputed.Dp; v != nil {
			h.Set(rsaDpKey, v.Bytes())
		}
		if v := privk.Precomputed.Dq; v != nil {
			h.Set(rsaDqKey, v.Bytes())
		}
		if v := privk.Precomputed.Qinv; v != nil {
			h.Set(rsaQiKey, v.Bytes())
		}
	}

	if pubk == nil {
		if v, ok := key.(*rsa.PublicKey); ok {
			pubk = v
		}
	}
	if pubk == nil {
		return
	}

	h.Set(rsaNKey, pubk.N.Bytes())
	h.Set(rsaEKey, base64.EncodeUint64ToString(uint64(pubk.E)))
}

func newRSAPublicKey(key *rsa.PublicKey) (*RSAPublicKey, error) {
	if key == nil {
		return nil, errors.New(`non-nil rsa.PublicKey required`)
	}

	hdr := NewHeaders()
	populateRSAHeaders(hdr, key)

	return &RSAPublicKey{
		headers: hdr,
	}, nil
}

func newRSAPrivateKey(key *rsa.PrivateKey) (*RSAPrivateKey, error) {
	if key == nil {
		return nil, errors.New(`non-nil rsa.PrivateKey required`)
	}

	if len(key.Primes) < 2 {
		return nil, errors.New("two primes required for RSA private key")
	}

	hdr := NewHeaders()
	populateRSAHeaders(hdr, key)
	return &RSAPrivateKey{
		headers: hdr,
	}, nil
}

func (k RSAPublicKey) MarshalJSON() (buf []byte, err error) {
	return json.Marshal(k.headers)
}

func (k *RSAPublicKey) UnmarshalJSON(data []byte) (err error) {
	h := NewHeaders()
	if err := json.Unmarshal(data, h); err != nil {
		return errors.Wrap(err, `failed to unmarshal public key`)
	}

	k.headers = h
	return nil
}

func (k RSAPrivateKey) MarshalJSON() (buf []byte, err error) {
	return json.Marshal(k.headers)
}

func (k *RSAPrivateKey) UnmarshalJSON(data []byte) (err error) {
	h := NewHeaders()
	if err := json.Unmarshal(data, h); err != nil {
		return errors.Wrap(err, `failed to unmarshal public key`)
	}

	k.headers = h
	return nil
}
*/

// Thumbprint returns the JWK thumbprint using the indicated
// hashing algorithm, according to RFC 7638
func (k RSAPrivateKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	var key rsa.PrivateKey
	if err := k.Materialize(&key); err != nil {
		return nil, errors.Wrap(err, `failed to materialize RSA private key`)
	}
	return rsaThumbprint(hash, &key.PublicKey)
}

func (k RSAPublicKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	var key rsa.PublicKey
	if err := k.Materialize(&key); err != nil {
		return nil, errors.Wrap(err, `failed to materialize RSA public key`)
	}
	return rsaThumbprint(hash, &key)
}

func rsaThumbprint(hash crypto.Hash, key *rsa.PublicKey) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(`{"e":"`)
	buf.WriteString(base64.EncodeUint64ToString(uint64(key.E)))
	buf.WriteString(`","kty":"RSA","n":"`)
	buf.WriteString(base64.EncodeToString(key.N.Bytes()))
	buf.WriteString(`"}`)

	h := hash.New()
	buf.WriteTo(h)
	return h.Sum(nil), nil
}
