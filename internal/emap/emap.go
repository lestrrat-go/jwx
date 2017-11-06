// Package emap provides utility functions for maps
//
// MergeMarshal/MergeUnmarshal are used to serialize/deserialize
// JSON object map which may have different required/known fields
// and possibly any number of extra parameters
package emap

import (
	"encoding/base64"
	"encoding/json"
	"reflect"

	"github.com/lestrrat/go-jwx/buffer"
	"github.com/pkg/errors"
)

var ErrInvalidJSON = errors.New("invalid JSON")

type Constructor interface {
	Construct(map[string]interface{}) error
}

func MergeMarshal(e interface{}, p map[string]interface{}) ([]byte, error) {
	buf, err := json.Marshal(e)
	if err != nil {
		return nil, errors.Wrap(err, `failed to marshal e`)
	}

	if len(p) == 0 {
		return buf, nil
	}

	ext, err := json.Marshal(p)
	if err != nil {
		return nil, errors.Wrap(err, `failed to marshal p`)
	}

	if len(buf) < 2 {
		return nil, ErrInvalidJSON
	}

	if buf[0] != '{' || buf[len(buf)-1] != '}' {
		return nil, errors.New("invalid JSON")
	}
	buf[len(buf)-1] = ','
	buf = append(buf, ext[1:]...)
	return buf, nil
}

func MergeUnmarshal(data []byte, c Constructor, ext *map[string]interface{}) error {
	m := make(map[string]interface{})
	if err := json.Unmarshal(data, &m); err != nil {
		return errors.Wrap(err, `failed to unmarshal`)
	}

	if err := c.Construct(m); err != nil {
		return errors.Wrap(err, `failed to construct map`)
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

func (h Hmap) GetInt64(name string, consume ...bool) (int64, error) {
	v, err := h.Get(name, reflect.TypeOf(int64(0)), consume...)
	if err != nil {
		return 0, errors.Wrapf(err, `failed to retrieve int64 value for key '%s'`, name)
	}

	return v.(int64), nil
}

func (h Hmap) GetByteSlice(name string, consume ...bool) ([]byte, error) {
	v, err := h.Get(name, reflect.TypeOf([]byte(nil)), consume...)
	if err != nil {
		return nil, errors.Wrapf(err, `failed to retrieve []byte value for key '%s'`, name)
	}

	// []byte is base64 encoded. decode!
	b := v.([]byte)
	enc := base64.StdEncoding
	out := make([]byte, enc.DecodedLen(len(b)))
	n, err := enc.Decode(out, b)
	if err != nil {
		return nil, errors.Wrapf(err, `failed to base64 decode for key '%s'`, name)
	}

	return out[:n], nil
}

func (h Hmap) GetString(name string, consume ...bool) (string, error) {
	v, err := h.Get(name, reflect.TypeOf(""), consume...)
	if err != nil {
		return "", errors.Wrapf(err, `failed to get string value for key '%s'`, name)
	}
	return v.(string), nil
}

func (h Hmap) GetStringSlice(name string, consume ...bool) ([]string, error) {
	v, err := h.Get(name, reflect.TypeOf([]interface{}{}), consume...)
	if err != nil {
		return nil, errors.Wrapf(err, `failed to get []string value for keu '%s'`, name)
	}

	s := v.([]interface{})
	out := make([]string, len(s))
	for i, s := range s {
		if val, ok := s.(string); ok {
			out[i] = val
		} else {
			return nil, errors.New("cannot cast string '" + name + "'")
		}
	}
	return out, nil
}

func (h Hmap) GetBuffer(name string, consume ...bool) (buffer.Buffer, error) {
	b := buffer.Buffer{}
	v, err := h.GetString(name, consume...)
	if err != nil {
		return b, errors.Wrapf(err, `failed to get buffer value for key '%s'`, name)
	}

	if err := b.Base64Decode([]byte(v)); err != nil {
		return b, errors.Wrapf(err, `failed to base64 decode for key '%s'`, name)
	}

	return b, nil
}
