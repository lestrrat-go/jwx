package jwk

import (
	"encoding/json"
	"errors"
	"io"
)

// LookupKeyId looks for keys matching the given key id. Note that the
// KeySet *may* contain multiple keys with the same key id
func (s KeySet) LookupKeyId(kid string) []JsonWebKey {
	var keys []JsonWebKey
	for _, key := range s.Keys {
		if key.Kid() == kid {
			keys = append(keys, key)
		}
	}
	return keys
}

func ParseKeySet(rdr io.Reader) (*KeySet, error) {
	m := make(map[string]interface{})
	if err := json.NewDecoder(rdr).Decode(&m); err != nil {
		return nil, err
	}

	raw, ok := m["keys"]
	if !ok {
		return nil, errors.New("missing 'keys' parameter")
	}

	v, ok := raw.([]interface{})
	if !ok {
		return nil, errors.New("invalid 'keys' parameter")
	}

	ks := KeySet{}
	for _, c := range v {
		conf, ok := c.(map[string]interface{})
		if !ok {
			return nil, errors.New("invalid element in 'keys'")
		}

		k, err := constructKey(conf)
		if err != nil {
			return nil, err
		}
		ks.Keys = append(ks.Keys, k)
	}

	return &ks, nil
}
