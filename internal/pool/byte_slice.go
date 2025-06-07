package pool

var bytesSlicePool = New(allocByteSlice, destroyByteSlice)

func GetByteSlice() *[]byte {
	//nolint:forcetypeassert
	return bytesSlicePool.Get()
}

func ReleaseByteSlice(b *[]byte) {
	// Put the slice back into the pool
	bytesSlicePool.Put(b)
}

func allocByteSlice() interface{} {
	buf := make([]byte, 0, 1024) // Preallocate a slice with a capacity of 1024 bytes
	return &buf
}

func destroyByteSlice(b *[]byte) {
	// Reset the slice to its zero value
	*b = (*b)[:0]
}
