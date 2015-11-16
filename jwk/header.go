package jwk

import (
	"net/url"

	"github.com/lestrrat/go-jwx/jwa"
)

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
