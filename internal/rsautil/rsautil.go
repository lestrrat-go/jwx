package rsautil

import (
	"crypto/rsa"
	"encoding/json"
	"math/big"

	"github.com/lestrrat/go-jwx/buffer"
	"github.com/pkg/errors"
)

type rawkey struct {
	N  buffer.Buffer `json:"n"`
	E  buffer.Buffer `json:"e"`
	D  buffer.Buffer `json:"d"`
	P  buffer.Buffer `json:"p"`
	Q  buffer.Buffer `json:"q"`
	Dp buffer.Buffer `json:"dp"`
	Dq buffer.Buffer `json:"dq"`
	Qi buffer.Buffer `json:"qi"`
}

func NewRawKeyFromPublicKey(pubkey *rsa.PublicKey) *rawkey {
	r := &rawkey{}
	r.N = buffer.Buffer(pubkey.N.Bytes())
	r.E = buffer.FromUint(uint64(pubkey.E))
	return r
}

func NewRawKeyFromPrivateKey(privkey *rsa.PrivateKey) *rawkey {
	r := NewRawKeyFromPublicKey(&privkey.PublicKey)
	r.D = buffer.Buffer(privkey.D.Bytes())
	r.P = buffer.Buffer(privkey.Primes[0].Bytes())
	r.Q = buffer.Buffer(privkey.Primes[1].Bytes())
	r.Dp = buffer.Buffer(privkey.Precomputed.Dp.Bytes())
	r.Dq = buffer.Buffer(privkey.Precomputed.Dq.Bytes())
	r.Qi = buffer.Buffer(privkey.Precomputed.Qinv.Bytes())
	return r
}

func PublicKeyFromJSON(data []byte) (*rsa.PublicKey, error) {
	r := rawkey{}
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, errors.Wrap(err, `failed to unmarshal public key`)
	}

	return r.GeneratePublicKey()
}

func PrivateKeyFromJSON(data []byte) (*rsa.PrivateKey, error) {
	r := rawkey{}
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, errors.Wrap(err, `failed to unmarshal private key`)
	}

	return r.GeneratePrivateKey()
}

func (r rawkey) GeneratePublicKey() (*rsa.PublicKey, error) {
	return &rsa.PublicKey{
		N: (&big.Int{}).SetBytes(r.N.Bytes()),
		E: int((&big.Int{}).SetBytes(r.E.Bytes()).Int64()),
	}, nil
}

func (r rawkey) GeneratePrivateKey() (*rsa.PrivateKey, error) {
	pubkey, err := r.GeneratePublicKey()
	if err != nil {
		return nil, errors.Wrap(err, `failed to generate public key`)
	}

	privkey := &rsa.PrivateKey{
		PublicKey: *pubkey,
		D:         (&big.Int{}).SetBytes(r.D.Bytes()),
		Primes: []*big.Int{
			(&big.Int{}).SetBytes(r.P.Bytes()),
			(&big.Int{}).SetBytes(r.Q.Bytes()),
		},
	}

	if r.Dp.Len() > 0 {
		privkey.Precomputed.Dp = (&big.Int{}).SetBytes(r.Dp.Bytes())
	}
	if r.Dq.Len() > 0 {
		privkey.Precomputed.Dq = (&big.Int{}).SetBytes(r.Dq.Bytes())
	}
	if r.Qi.Len() > 0 {
		privkey.Precomputed.Qinv = (&big.Int{}).SetBytes(r.Qi.Bytes())
	}

	return privkey, nil
}
