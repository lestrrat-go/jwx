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
	case "key_ops":
		return h.KeyOps, nil
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
		switch value.(type) {
		case jwa.SignatureAlgorithm:
			h.Algorithm = value.(jwa.SignatureAlgorithm).String()
		case jwa.KeyEncryptionAlgorithm:
			h.Algorithm = value.(jwa.KeyEncryptionAlgorithm).String()
		default:
			return ErrInvalidHeaderValue
		}
		return nil
	case "kid":
		v, ok := value.(string)
		if !ok {
			return ErrInvalidHeaderValue
		}
		h.KeyID = v
		return nil
	case "key_ops":
		v, ok := value.([]KeyOperation)
		if !ok {
			return ErrInvalidHeaderValue
		}
		h.KeyOps = v
		return nil
	case "kty":
		switch value.(type) {
		case jwa.KeyType:
			h.KeyType = value.(jwa.KeyType)
		case string:
			h.KeyType = jwa.KeyType(value.(string))
		default:
			return ErrInvalidHeaderValue
		}
		return nil
	case "use":
		v, ok := value.(string)
		if !ok {
			return ErrInvalidHeaderValue
		}
		h.KeyUsage = v
		return nil
	case "x5t":
		v, ok := value.(string)
		if !ok {
			return ErrInvalidHeaderValue
		}
		h.X509CertThumbprint = v
		return nil
	case "x5t#256":
		v, ok := value.(string)
		if !ok {
			return ErrInvalidHeaderValue
		}
		h.X509CertThumbprintS256 = v
		return nil
	case "x5c":
		v, ok := value.([]string)
		if !ok {
			return ErrInvalidHeaderValue
		}
		h.X509CertChain = v
		return nil
	case "x5u":
		switch value.(type) {
		case string:
			u, err := url.Parse(value.(string))
			if err != nil {
				return ErrInvalidHeaderValue
			}
			h.X509Url = u
		case *url.URL:
			h.X509Url = value.(*url.URL)
		default:
			return ErrInvalidHeaderName
		}
		return nil
	default:
		return ErrInvalidHeaderName
	}
}
