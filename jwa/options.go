package jwa

import "github.com/lestrrat-go/option"

type NewKeyAlgorithmOption interface {
	option.Interface
	newKeyAlgorithmOption()
}

type newKeyAlgorithmOption struct {
	option.Interface
}

func (newKeyAlgorithmOption) newKeyAlgorithmOption() {}

type identSymmetricAlgorithm struct{}

func WithIsSymmetric(v bool) NewKeyAlgorithmOption {
	return newKeyAlgorithmOption{option.New(identSymmetricAlgorithm{}, v)}
}
