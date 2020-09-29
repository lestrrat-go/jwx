// +build go1.15

package jwk

import (
	"math/big"
)

func bigIntFillBytes(v *big.Int, buf []byte) []byte {
	v.FillBytes(buf)
	return buf
}
