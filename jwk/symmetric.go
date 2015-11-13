package jwk

func (s SymmetricKey) Materialize() (interface{}, error) {
	return s.Octets(), nil
}

func (s SymmetricKey) Octets() []byte {
	return s.Key
}
