package jwebb

var UnregisterHPKEAlgorithm = unregisterHPKEAlgorithm

func UnregisterMLKEMAlgorithm(alg string) {
	muMLKEMAlgs.Lock()
	defer muMLKEMAlgs.Unlock()
	delete(mlkemAlgSet, alg)
}

func UnregisterMLKEMDirectAlgorithm(alg string) {
	muMLKEMAlgs.Lock()
	defer muMLKEMAlgs.Unlock()
	delete(mlkemDirectAlgSet, alg)
}
