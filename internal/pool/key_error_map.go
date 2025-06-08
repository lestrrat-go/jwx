package pool

var keyToErrorMapPool = New(allocKeyToErrorMap, destroyKeyToErrorMap)

func allocKeyToErrorMap() interface{} {
	return make(map[string]error)
}

func GetKeyToErrorMap() map[string]error {
	return keyToErrorMapPool.Get()
}

func ReleaseKeyToErrorMap(m map[string]error) {
	keyToErrorMapPool.Put(m)
}

func destroyKeyToErrorMap(m map[string]error) {
	for key := range m {
		delete(m, key)
	}
}
