package pool

var mapPool = New(allocMap, destroyMap)

func allocMap() interface{} {
	m := make(map[string]interface{})
	return &m
}

func destroyMap(m *map[string]interface{}) {
	if len(*m) > 16 {
		*m = make(map[string]interface{})
		return
	}

	for key := range *m {
		delete(*m, key)
	}
}

func GetMap() *map[string]interface{} {
	return mapPool.Get()
}

func ReleaseMap(m *map[string]interface{}) {
	mapPool.Put(m)
}
