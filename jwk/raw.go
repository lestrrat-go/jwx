package jwk

import (
	"bytes"
	"encoding/base64"
	"errors"
	"reflect"
)

func (r rawKey) Get(name string, t reflect.Type) (interface{}, error) {
	v, ok := r[name]
	if !ok || reflect.TypeOf(v) == nil {
		return nil, errors.New("missing '" + name + "'")
	}

	rv := reflect.ValueOf(v)

	if !rv.Type().ConvertibleTo(t) {
		return nil, errors.New("invalid '" + name + "'")
	}

	return rv.Convert(t).Interface(), nil
}

func (r rawKey) GetByteSlice(name string) ([]byte, error) {
	v, err := r.Get(name, reflect.TypeOf([]byte(nil)))
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

func (r rawKey) GetString(name string) (string, error) {
	v, err := r.Get(name, reflect.TypeOf(""))
	if err != nil {
		return "", err
	}
	return v.(string), nil
}
