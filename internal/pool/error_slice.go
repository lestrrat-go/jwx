package pool

var errorSlicePool = New[[]error](allocErrorSlice, freeErrorSlice)

func allocErrorSlice() []error {
	return make([]error, 0, 1)
}

func freeErrorSlice(s []error) []error {
	// Defensive: scrub the entire backing array, not just s[:len(s)]. The
	// pooled errors may reference request data; clearing the full capacity
	// keeps stale values from staying reachable in the pool's backing
	// storage until they happen to be overwritten.
	s = s[:cap(s)]
	clear(s)
	return s[:0]
}

func ErrorSlice() *Pool[[]error] {
	return errorSlicePool
}
