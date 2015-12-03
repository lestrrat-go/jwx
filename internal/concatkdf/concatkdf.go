package concatkdf

import (
	"crypto"
	"encoding/binary"
	"hash"

	"github.com/lestrrat/go-jwx/buffer"
)

type KDF struct {
	buf       []byte
	hash      hash.Hash
	otherinfo []byte
	round     uint32
	z         []byte
}

func New(hash crypto.Hash, alg, Z, apu, apv, pubinfo, privinfo []byte) *KDF {
	algbuf := buffer.Buffer(alg).NData()
	apubuf := buffer.Buffer(apu).NData()
	apvbuf := buffer.Buffer(apv).NData()

	concat := make([]byte, len(algbuf)+len(apubuf)+len(apvbuf)+len(pubinfo)+len(privinfo))
	n := copy(concat, algbuf)
	n += copy(concat[n:], apubuf)
	n += copy(concat[n:], apvbuf)
	n += copy(concat[n:], pubinfo)
	n += copy(concat[n:], privinfo)

	return &KDF{
		hash:      hash.New(),
		otherinfo: concat,
		round:     1,
		z:         Z,
	}
}

func (k *KDF) Read(buf []byte) (int, error) {
	h := k.hash
	for len(buf) > len(k.buf) {
		h.Reset()

		binary.Write(h, binary.BigEndian, k.round)
		h.Write(k.z)
		h.Write(k.otherinfo)

		k.buf = append(k.buf, h.Sum(nil)...)
		k.round++
	}

	n := copy(buf, k.buf[:len(buf)])
	k.buf = k.buf[len(buf):]
	return n, nil
}
