package pool

var mapPool = New(allocMap, destroyMap)

func Map() *Pool[*map[string]any] {
	return mapPool
}

func allocMap() any {
	m := make(map[string]any)
	return &m
}

func destroyMap(m *map[string]any) {
	if len(*m) > 16 {
		*m = make(map[string]any)
		return
	}

	for key := range *m {
		delete(*m, key)
	}
}
