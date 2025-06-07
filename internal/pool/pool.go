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
	//nolint:forcetypeassert
	return bytesBufferPool.Get().(*bytes.Buffer)
}

func ReleaseBytesBuffer(b *bytes.Buffer) {
	b.Reset()
	bytesBufferPool.Put(b)
}

var bytesSlicePool = sync.Pool{
	New: allocByteSlice,
}

func allocByteSlice() interface{} {
	buf := make([]byte, 0, 1024) // Preallocate a slice with a capacity of 1024 bytes
	return &buf
}

func GetByteSlice() *[]byte {
	//nolint:forcetypeassert
	return bytesSlicePool.Get().(*[]byte)
}

func ReleaseByteSlice(b *[]byte) {
	// Reset the slice to its zero value
	*b = (*b)[:0]
	// Put the slice back into the pool
	bytesSlicePool.Put(b)
}

var bigIntPool = sync.Pool{
	New: allocBigInt,
}

func allocBigInt() interface{} {
	return &big.Int{}
}

func GetBigInt() *big.Int {
	//nolint:forcetypeassert
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
	//nolint:forcetypeassert
	return keyToErrorMapPool.Get().(map[string]error)
}

func ReleaseKeyToErrorMap(m map[string]error) {
	for key := range m {
		delete(m, key)
	}
}
