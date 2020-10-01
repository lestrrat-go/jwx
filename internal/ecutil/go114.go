// +build !go1.15

package ecutil

import (
	"math/big"
)

func bigIntFillBytes(v *big.Int, buf []byte) []byte {
	data := v.Bytes()
	if len(data) > len(buf) {
		panic("ecutil: invalid call to bigIntFillBytes (len(data) > len(buf))")
	}

	copy(buf[len(buf)-len(data):], data)
	return buf
}
