package jwk

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"encoding/binary"
	"math/big"

	"github.com/lestrrat-go/jwx/internal/base64"
	"github.com/pkg/errors"
)

func NewRSAPublicKey() RSAPublicKey {
	return newRSAPublicKey()
}

func newRSAPublicKey() *rsaPublicKey {
	return &rsaPublicKey{
		privateParams: make(map[string]interface{}),
	}
}

func NewRSAPrivateKey() RSAPrivateKey {
	return newRSAPrivateKey()
}

func newRSAPrivateKey() *rsaPrivateKey {
	return &rsaPrivateKey{
		privateParams: make(map[string]interface{}),
	}
}

func (k *rsaPrivateKey) FromRaw(v interface{}) error {
	switch x := v.(type) {
	case rsa.PrivateKey:
		v = &x
	}

	rawKey, ok := v.(*rsa.PrivateKey)
	if !ok {
		return errors.Errorf(`(jwk.RSAPrivateKey).FromRaw requires rsa.PrivateKey as the argument (%T)`, v)
	}

	k.d = rawKey.D.Bytes()
	if len(rawKey.Primes) < 2 {
		return errors.Errorf(`invalid number of primes in rsa.PrivateKey: need 2, got %d`, len(rawKey.Primes))
	}

	k.p = rawKey.Primes[0].Bytes()
	k.q = rawKey.Primes[1].Bytes()

	if v := rawKey.Precomputed.Dp; v != nil {
		k.dp = v.Bytes()
	}
	if v := rawKey.Precomputed.Dq; v != nil {
		k.dq = v.Bytes()
	}
	if v := rawKey.Precomputed.Qinv; v != nil {
		k.qi = v.Bytes()
	}

	k.n = rawKey.PublicKey.N.Bytes()
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, uint64(rawKey.PublicKey.E))
	i := 0
	for ; i < len(data); i++ {
		if data[i] != 0x0 {
			break
		}
	}
	k.e = data[i:]

	return nil
}

func (k *rsaPublicKey) FromRaw(v interface{}) error {
	switch x := v.(type) {
	case rsa.PublicKey:
		v = &x
	}

	rawKey, ok := v.(*rsa.PublicKey)
	if !ok {
		return errors.Errorf(`(jwk.RSAPublicKey).FromRaw requires rsa.PublicKey as the argument (%T)`, v)
	}

	k.n = rawKey.N.Bytes()
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, uint64(rawKey.E))
	i := 0
	for ; i < len(data); i++ {
		if data[i] != 0x0 {
			break
		}
	}
	k.e = data[i:]

	return nil
}

func (k *rsaPrivateKey) Materialize(v interface{}) error {
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

	pubk := newRSAPublicKey()
	pubk.n = k.n
	pubk.e = k.e
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
func (k *rsaPublicKey) Materialize(v interface{}) error {
	var key rsa.PublicKey

	var n, e big.Int
	n.SetBytes(k.n)
	e.SetBytes(k.e)

	key.N = &n
	key.E = int(e.Int64())

	return assignMaterializeResult(v, &key)
}

func (k rsaPrivateKey) PublicKey() (RSAPublicKey, error) {
	var key rsa.PrivateKey
	if err := k.Materialize(&key); err != nil {
		return nil, errors.Wrap(err, `failed to materialize key to generate public key`)
	}

	newKey := NewRSAPublicKey()
	if err := newKey.FromRaw(&key.PublicKey); err != nil {
		return nil, errors.Wrap(err, `failed to initialize RSAPublicKey`)
	}
	return newKey, nil
}

// Thumbprint returns the JWK thumbprint using the indicated
// hashing algorithm, according to RFC 7638
func (k rsaPrivateKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	var key rsa.PrivateKey
	if err := k.Materialize(&key); err != nil {
		return nil, errors.Wrap(err, `failed to materialize RSA private key`)
	}
	return rsaThumbprint(hash, &key.PublicKey)
}

func (k rsaPublicKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
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
