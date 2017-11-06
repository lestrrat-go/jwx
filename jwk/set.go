package jwk

import "github.com/pkg/errors"

// LookupKeyID looks for keys matching the given key id. Note that the
// Set *may* contain multiple keys with the same key id
func (s Set) LookupKeyID(kid string) []Key {
	var keys []Key
	for _, key := range s.Keys {
		if key.Kid() == kid {
			keys = append(keys, key)
		}
	}
	return keys
}

func constructSet(m map[string]interface{}) (*Set, error) {
	raw, ok := m["keys"]
	if !ok {
		return nil, errors.New("missing 'keys' parameter")
	}

	v, ok := raw.([]interface{})
	if !ok {
		return nil, errors.New("invalid 'keys' parameter")
	}

	ks := Set{}
	for _, c := range v {
		conf, ok := c.(map[string]interface{})
		if !ok {
			return nil, errors.New("invalid element in 'keys'")
		}

		k, err := constructKey(conf)
		if err != nil {
			return nil, errors.Wrap(err, `failed to construct key from map`)
		}
		ks.Keys = append(ks.Keys, k)
	}

	return &ks, nil
}
