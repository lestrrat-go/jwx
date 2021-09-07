package pool

import (
	"bytes"
	"math/big"
	"sync"
)

var bytesBufferPool = sync.Pool{
	New: allocBytesBuffer,
}

func allocBytesBuffer() interface{} {
	return &bytes.Buffer{}
}

func GetBytesBuffer() *bytes.Buffer {
	return bytesBufferPool.Get().(*bytes.Buffer)
}

func ReleaseBytesBuffer(b *bytes.Buffer) {
	b.Reset()
	bytesBufferPool.Put(b)
}

var bigIntPool = sync.Pool{
	New: allocBigInt,
}

func allocBigInt() interface{} {
	return &big.Int{}
}

func GetBigInt() *big.Int {
	return bigIntPool.Get().(*big.Int)
}

func ReleaseBigInt(i *big.Int) {
	bigIntPool.Put(i.SetInt64(0))
}

var keyToErrorMapPool = sync.Pool{
	New: allocKeyToErrorMap,
}

func allocKeyToErrorMap() interface{} {
	return make(map[string]error)
}

func GetKeyToErrorMap() map[string]error {
	return keyToErrorMapPool.Get().(map[string]error)
}

func ReleaseKeyToErrorMap(m map[string]error) {
	for key := range m {
		delete(m, key)
	}
}
