package pool

import (
	"math/big"
)

var bigIntPool = New(allocBigInt, destroyBigInt)

func allocBigInt() interface{} {
	return &big.Int{}
}

func destroyBigInt(i *big.Int) {
	i.SetInt64(0)
}

func GetBigInt() *big.Int {
	return bigIntPool.Get()
}

func ReleaseBigInt(i *big.Int) {
	bigIntPool.Put(i)
}
