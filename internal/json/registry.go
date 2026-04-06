package json

import (
	"fmt"
	"reflect"
	"sync"
)

// CustomDecoder is the interface we expect from RegisterCustomField in jws, jwe, jwk, and jwt packages.
type CustomDecoder interface {
	// Decode takes a JSON encoded byte slice and returns the desired
	// decoded value, which will be used as the value for that field
	// registered through RegisterCustomField
	Decode([]byte) (any, error)
}

// CustomDecodeFunc is a stateless, function-based implementation of CustomDecoder
type CustomDecodeFunc func([]byte) (any, error)

func (fn CustomDecodeFunc) Decode(data []byte) (any, error) {
	return fn(data)
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

type Registry struct {
	mu   *sync.RWMutex
	ctrs map[string]CustomDecoder
}

func NewRegistry() *Registry {
	return &Registry{
		mu:   &sync.RWMutex{},
		ctrs: make(map[string]CustomDecoder),
	}
}

// Register registers a custom decoder for the given field name.
// If object is nil, the registration is removed.
// If object implements CustomDecoder, it is used directly.
// Otherwise, an objectTypeDecoder is created using reflect.
// New code should prefer RegisterTyped for compile-time type safety.
func (r *Registry) Register(name string, object any) {
	if object == nil {
		r.mu.Lock()
		defer r.mu.Unlock()
		delete(r.ctrs, name)
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if ctr, ok := object.(CustomDecoder); ok {
		r.ctrs[name] = ctr
	} else {
		r.ctrs[name] = &objectTypeDecoder{
			typ:  reflect.TypeOf(object),
			name: name,
		}
	}
}

// RegisterTyped registers a generic TypedDecoder[T] for the given field name.
func RegisterTyped[T any](r *Registry, name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ctrs[name] = &TypedDecoder[T]{name: name}
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
	if err := Unmarshal([]byte(raw), &decoded); err != nil {
		return nil, fmt.Errorf(`failed to decode field %s: %w`, name, err)
	}
	return decoded, nil
}
