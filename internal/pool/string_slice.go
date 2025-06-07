package pool

var stringSlicePool = New(allocStringSlice, destroyStringSlice)

func allocStringSlice() interface{} {
	ret := make([]string, 0, 16)
	return &ret
}

func destroyStringSlice(s *[]string) {
	*s = (*s)[:0]
}

func GetStringSlice() *[]string {
	//nolint:forcetypeassert
	return stringSlicePool.Get()
}

func ReleaseStringSlice(s *[]string) {
	stringSlicePool.Put(s)
}
