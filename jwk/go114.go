// +build !go1.15

package jwk

import (
	"math/big"
)

func bigIntFillBytes(v *big.Int, buf []byte) []byte {
	data := v.Bytes()
	if len(data) > len(buf) {
		panic("jwx/jwk: invalid call to newFixedSizeBuffer (len(data) > len(buf))")
	}

	copy(buf[len(buf)-len(data):], data)
	return buf
}
