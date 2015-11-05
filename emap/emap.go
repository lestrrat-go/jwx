// emap provides utility functions for maps
//
// MergMarshal/MergeUnmarshal are used to serialize/deserialize 
// JSON object map which may have different required/known fields 
// and possibly any number of extra parameters
package emap

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
)

type Constructor interface {
	Construct(map[string]interface{}) error
}

func MergeMarshal(e interface{}, p map[string]interface{}) ([]byte, error) {
	buf, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}

	if len(p) == 0 {
		return buf, nil
	}

	ext, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}

	if !bytes.HasSuffix(buf, []byte{'}'}) {
		return nil, errors.New("invalid JSON")
	}
	if !bytes.HasPrefix(ext, []byte{'{'}) {
		return nil, errors.New("invalid JSON")
	}
	buf[len(buf)-1] = ','
	buf = append(buf, ext[1:]...)
	return buf, nil
}

func MergeUnmarshal(data []byte, c Constructor, ext *map[string]interface{}) error {
	m := make(map[string]interface{})
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}

	if err := c.Construct(m); err != nil {
		return err
	}

	if len(m) > 0 {
		*ext = m
	}
	return nil
}

// Hmap is used to parse through the JSON object from which to
// construct the actual JWK's. The only reason this exists is to
// allow the parser to decide which type of key to create based
// upon which keys are present in the parsed JSON object
type Hmap map[string]interface{}

func (h Hmap) Get(name string, t reflect.Type, consume ...bool) (interface{}, error) {
	v, ok := h[name]
	if !ok {
		return nil, errors.New("missing '" + name + "'")
	}

	if len(consume) == 0 || consume[0] {
		delete(h, name)
	}

	rv := reflect.ValueOf(v)
	if !rv.IsValid() || !rv.Type().ConvertibleTo(t) {
		return nil, errors.New("invalid '" + name + "'")
	}

	return rv.Convert(t).Interface(), nil
}

func (h Hmap) GetByteSlice(name string, consume ...bool) ([]byte, error) {
	v, err := h.Get(name, reflect.TypeOf([]byte(nil)), consume...)
	if err != nil {
		return nil, err
	}

	// []byte is base64 encoded. decode!
	b := v.([]byte)
	enc := base64.StdEncoding
	out := make([]byte, enc.DecodedLen(len(b)))
	enc.Decode(out, b)

	out = bytes.TrimRight(out, "\x00")

	return out, nil
}

func (h Hmap) GetString(name string, consume ...bool) (string, error) {
	v, err := h.Get(name, reflect.TypeOf(""), consume...)
	if err != nil {
		return "", err
	}
	return v.(string), nil
}

func (h Hmap) GetStringSlice(name string, consume ...bool) ([]string, error) {
	v, err := h.Get(name, reflect.TypeOf([]string{}), consume...)
	if err != nil {
		return nil, err
	}
	return v.([]string), nil
}

