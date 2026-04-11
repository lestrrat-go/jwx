package json

import (
	stdjson "encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"reflect"
	"sync"
)

// customDecoder is the internal interface for field decoders stored in the registry.
// It returns any because different fields decode to different types.
type customDecoder interface {
	Decode([]byte) (any, error)
}

// CustomDecoder is the public generic interface for custom field decoders.
type CustomDecoder[T any] interface {
	Decode([]byte) (T, error)
}

// CustomDecodeFunc is a function-based implementation of CustomDecoder[T].
type CustomDecodeFunc[T any] func([]byte) (T, error)

func (fn CustomDecodeFunc[T]) Decode(data []byte) (T, error) {
	return fn(data)
}

// customDecoderAdapter wraps a CustomDecoder[T] to satisfy the internal customDecoder interface.
type customDecoderAdapter[T any] struct {
	dec CustomDecoder[T]
}

func (a *customDecoderAdapter[T]) Decode(data []byte) (any, error) {
	return a.dec.Decode(data)
}

// objectTypeDecoder is a reflect-based decoder used by the untyped Register path.
type objectTypeDecoder struct {
	typ  reflect.Type
	name string
}

func (dec *objectTypeDecoder) Decode(data []byte) (any, error) {
	ptr := reflect.New(dec.typ).Interface()
	if err := Unmarshal(data, ptr); err != nil {
		return nil, fmt.Errorf(`failed to decode field %s: %w`, dec.name, err)
	}
	return reflect.ValueOf(ptr).Elem().Interface(), nil
}

// TypedDecoder is a generic decoder that unmarshals JSON into a concrete type T,
// eliminating the need for reflect.New.
type TypedDecoder[T any] struct {
	name string
}

func (dec *TypedDecoder[T]) Decode(data []byte) (any, error) {
	var v T
	if err := Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf(`failed to decode field %s: %w`, dec.name, err)
	}
	return v, nil
}

// useNumberUnmarshalers is a pre-built json/v2 option that intercepts
// unmarshalling of JSON numbers into any, producing json.Number instead
// of float64.
var useNumberUnmarshalers = jsonv2.WithUnmarshalers(
	jsonv2.UnmarshalFromFunc(func(dec *jsontext.Decoder, val *any) error {
		if dec.PeekKind() != '0' {
			return jsonv2.SkipFunc
		}
		raw, err := dec.ReadValue()
		if err != nil {
			return err
		}
		*val = stdjson.Number(raw.String())
		return nil
	}),
)

type Registry struct {
	mu   *sync.RWMutex
	ctrs map[string]customDecoder
}

func NewRegistry() *Registry {
	return &Registry{
		mu:   &sync.RWMutex{},
		ctrs: make(map[string]customDecoder),
	}
}

// RegisterTyped registers a generic TypedDecoder[T] for the given field name.
func RegisterTyped[T any](r *Registry, name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ctrs[name] = &TypedDecoder[T]{name: name}
}

// RegisterCustomDecoder registers a CustomDecoder[T] for the given field name.
func RegisterCustomDecoder[T any](r *Registry, name string, dec CustomDecoder[T]) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ctrs[name] = &customDecoderAdapter[T]{dec: dec}
}

// Register registers a decoder for the given field name using the untyped
// dispatch path. If object is nil, the registration is removed.
// If object implements customDecoder, it is used directly.
// Otherwise, an objectTypeDecoder is created using reflect.
//
// This is used internally by WithTypedField for per-parse local registries.
// New code should prefer RegisterTyped or RegisterCustomDecoder.
func (r *Registry) Register(name string, object any) {
	if object == nil {
		r.Unregister(name)
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if ctr, ok := object.(customDecoder); ok {
		r.ctrs[name] = ctr
	} else {
		r.ctrs[name] = &objectTypeDecoder{
			typ:  reflect.TypeOf(object),
			name: name,
		}
	}
}

// Unregister removes the decoder for the given field name.
func (r *Registry) Unregister(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.ctrs, name)
}

// Decode decodes the raw JSON value using the registered decoder for the
// given field name. If no decoder is registered, the raw value is decoded
// into any.
func (r *Registry) Decode(name string, raw RawMessage) (any, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if ctr, ok := r.ctrs[name]; ok {
		v, err := ctr.Decode([]byte(raw))
		if err != nil {
			return nil, fmt.Errorf(`failed to decode field %s: %w`, name, err)
		}
		return v, nil
	}

	var decoded any
	if GetUseNumber() {
		if err := jsonv2.Unmarshal([]byte(raw), &decoded, useNumberUnmarshalers); err != nil {
			return nil, fmt.Errorf(`failed to decode field %s: %w`, name, err)
		}
	} else {
		if err := Unmarshal([]byte(raw), &decoded); err != nil {
			return nil, fmt.Errorf(`failed to decode field %s: %w`, name, err)
		}
	}
	return decoded, nil
}
