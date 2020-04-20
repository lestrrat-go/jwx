package jwa_test

type stringer struct {
	src string
}

func (s stringer) String() string {
	return s.src
}
