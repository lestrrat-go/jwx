package jwk

import (
	"net/url"

	"github.com/lestrrat/go-jwx/jwa"
)

// Get returns the value of the corresponding header. `key` should
// be the same as the JSON key name (e.g. `alg`, `kid`, etc)
func (h *EssentialHeader) Get(key string) (interface{}, error) {
	switch key {
	case "alg":
		return h.Algorithm, nil
	case "kid":
		return h.KeyID, nil
	case "kty":
		return h.KeyType, nil
	case "use":
		return h.KeyUsage, nil
	case "x5t":
		return h.X509CertThumbprint, nil
	case "x5t#256":
		return h.X509CertThumbprintS256, nil
	case "x5c":
		return h.X509CertChain, nil
	case "x5u":
		return h.X509Url, nil
	}
	return nil, ErrInvalidHeaderName
}

// Set sets the value of the corresponding header. `key` should
// be the same as the JSON key name (e.g. `alg`, `kid`, etc)
func (h *EssentialHeader) Set(key string, value interface{}) error {
	switch key {
	case "alg":
		v, ok := value.(string)
		if !ok {
			return ErrInvalidHeaderValue
		}
		h.Algorithm = v
	case "kid":
		v, ok := value.(string)
		if !ok {
			return ErrInvalidHeaderValue
		}
		h.KeyID = v
	case "kty":
		var v jwa.KeyType
		s, ok := value.(string)
		if ok {
			v = jwa.KeyType(s)
		} else {
			v, ok = value.(jwa.KeyType)
			if !ok {
				return ErrInvalidHeaderValue
			}
		}
		h.KeyType = v
	case "use":
		v, ok := value.(string)
		if !ok {
			return ErrInvalidHeaderValue
		}
		h.KeyUsage = v
	case "x5t":
		v, ok := value.(string)
		if !ok {
			return ErrInvalidHeaderValue
		}
		h.X509CertThumbprint = v
	case "x5t#256":
		v, ok := value.(string)
		if !ok {
			return ErrInvalidHeaderValue
		}
		h.X509CertThumbprintS256 = v
	case "x5c":
		v, ok := value.([]string)
		if !ok {
			return ErrInvalidHeaderValue
		}
		h.X509CertChain = v
	case "x5u":
		v, ok := value.(string)
		if !ok {
			return ErrInvalidHeaderValue
		}
		u, err := url.Parse(v)
		if err != nil {
			return ErrInvalidHeaderValue
		}
		h.X509Url = u
	}
	return ErrInvalidHeaderName
}
