package pool

import (
	"bytes"
)

var bytesBufferPool = New(allocBytesBuffer, destroyBytesBuffer)

func destroyBytesBuffer(b *bytes.Buffer) {
	b.Reset()
}

func allocBytesBuffer() interface{} {
	return &bytes.Buffer{}
}

func GetBytesBuffer() *bytes.Buffer {
	//nolint:forcetypeassert
	return bytesBufferPool.Get()
}

func ReleaseBytesBuffer(b *bytes.Buffer) {
	bytesBufferPool.Put(b)
}
