package jwk

import (
	"bytes"
	"encoding/json/jsontext"
	"fmt"
	"iter"
	"maps"
	"reflect"
	"slices"

	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/lestrrat-go/jwx/v4/internal/pool"
)

const keysKey = `keys` // appease linter

func newSet() *set {
	return &set{
		privateParams: make(map[string]any),
	}
}

// NewSet creates and empty `jwk.Set` object
func NewSet() Set {
	return newSet()
}

func (s *set) Set(n string, v any) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if n == keysKey {
		vl, ok := v.([]Key)
		if !ok {
			return fmt.Errorf(`value for field "keys" must be []jwk.Key`)
		}
		s.keys = vl
		return nil
	}

	s.privateParams[n] = v
	return nil
}

func (s *set) Field(name string) (any, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	v, ok := s.privateParams[name]
	return v, ok
}

func (s *set) Key(idx int) (Key, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if idx >= 0 && idx < len(s.keys) {
		return s.keys[idx], true
	}
	return nil, false
}

func (s *set) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.keys)
}

// indexNL is Index(), but without the locking
func (s *set) indexNL(key Key) int {
	for i, k := range s.keys {
		if k == key {
			return i
		}
	}
	return -1
}

func (s *set) Index(key Key) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.indexNL(key)
}

func (s *set) AddKey(key Key) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rv := reflect.ValueOf(key)
	if !rv.IsValid() {
		return fmt.Errorf(`(jwk.Set).AddKey: nil key`)
	}
	switch rv.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Chan, reflect.Func, reflect.Map, reflect.Slice:
		if rv.IsNil() {
			return fmt.Errorf(`(jwk.Set).AddKey: nil key`)
		}
	}

	if i := s.indexNL(key); i > -1 {
		return fmt.Errorf(`(jwk.Set).AddKey: key already exists`)
	}
	s.keys = append(s.keys, key)
	return nil
}

func (s *set) Remove(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.privateParams, name)
	return nil
}

func (s *set) RemoveKey(key Key) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, k := range s.keys {
		if k == key {
			switch i {
			case 0:
				s.keys = s.keys[1:]
			case len(s.keys) - 1:
				s.keys = s.keys[:i]
			default:
				s.keys = append(s.keys[:i], s.keys[i+1:]...)
			}
			return nil
		}
	}
	return fmt.Errorf(`(jwk.Set).RemoveKey: specified key does not exist in set`)
}

func (s *set) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.keys = nil
	s.privateParams = make(map[string]any)
	return nil
}

func (s *set) Keys() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ret := make([]string, len(s.privateParams))
	var i int
	for k := range s.privateParams {
		ret[i] = k
		i++
	}
	return ret
}

func (s *set) MarshalJSON() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	buf := pool.BytesBuffer().Get()
	defer pool.BytesBuffer().Put(buf)
	enc := json.NewEncoder(buf)

	fields := make([]string, 0, 1+len(s.privateParams))
	fields = append(fields, keysKey)
	for k := range s.privateParams {
		fields = append(fields, k)
	}
	slices.Sort(fields)

	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return nil, fmt.Errorf(`failed to write begin object: %w`, err)
	}
	for _, field := range fields {
		if err := enc.WriteToken(jsontext.String(field)); err != nil {
			return nil, fmt.Errorf(`failed to write field name %q: %w`, field, err)
		}
		if field != keysKey {
			if err := json.MarshalEncode(enc, s.privateParams[field]); err != nil {
				return nil, fmt.Errorf(`failed to marshal field %q: %w`, field, err)
			}
		} else {
			if err := enc.WriteToken(jsontext.BeginArray); err != nil {
				return nil, fmt.Errorf(`failed to write begin array: %w`, err)
			}
			for i, k := range s.keys {
				if err := json.MarshalEncode(enc, k); err != nil {
					return nil, fmt.Errorf(`failed to marshal key #%d: %w`, i, err)
				}
			}
			if err := enc.WriteToken(jsontext.EndArray); err != nil {
				return nil, fmt.Errorf(`failed to write end array: %w`, err)
			}
		}
	}
	if err := enc.WriteToken(jsontext.EndObject); err != nil {
		return nil, fmt.Errorf(`failed to write end object: %w`, err)
	}

	ret := make([]byte, buf.Len())
	copy(ret, buf.Bytes())
	return ret, nil
}

func (s *set) setMaxKeys(n int) {
	s.maxKeys = n
}

func (s *set) setRejectDuplicateKID(v bool) {
	s.rejectDuplicateKID = v
}

func (s *set) UnmarshalJSON(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.privateParams = make(map[string]any)
	s.keys = nil

	var options []ParseOption
	var ignoreParseError bool
	if dc := s.dc; dc != nil {
		if localReg := dc.Registry(); localReg != nil {
			options = append(options, withLocalRegistry(localReg))
		}
		ignoreParseError = dc.IgnoreParseError()
	}

	maxK := s.maxKeys
	if maxK <= 0 {
		maxK = int(maxKeys.Load())
	}
	rejectDupKid := s.rejectDuplicateKID || rejectDuplicateKID.Load()

	var sawKeysField bool
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.ReadToken()
	if err != nil {
		return fmt.Errorf(`error reading token: %w`, err)
	}
	if tok.Kind() != '{' {
		return fmt.Errorf(`expected '{' but got '%c'`, tok.Kind())
	}
	for dec.PeekKind() != '}' {
		tok, err := dec.ReadToken()
		if err != nil {
			return fmt.Errorf(`error reading token: %w`, err)
		}
		fieldName := tok.String()
		switch fieldName {
		case "keys":
			sawKeysField = true
			var list []json.RawMessage
			if err := json.UnmarshalDecode(dec, &list); err != nil {
				return fmt.Errorf(`failed to decode "keys": %w`, err)
			}

			if len(list) > maxK {
				return fmt.Errorf(`too many keys in "keys" array: got %d, max %d`, len(list), maxK)
			}

			var seenKIDs map[string]struct{}
			if rejectDupKid {
				seenKIDs = make(map[string]struct{}, len(list))
			}
			for i, keysrc := range list {
				key, err := doParseKey(keysrc, options...)
				if err != nil {
					if !ignoreParseError {
						return fmt.Errorf(`failed to decode key #%d in "keys": %w`, i, err)
					}
					continue
				}
				if seenKIDs != nil {
					if kid, ok := key.KeyID(); ok && kid != "" {
						if _, dup := seenKIDs[kid]; dup {
							return fmt.Errorf(`duplicate "kid" %q in "keys" array`, kid)
						}
						seenKIDs[kid] = struct{}{}
					}
				}
				s.keys = append(s.keys, key)
			}
		default:
			var v any
			raw, err := dec.ReadValue()
			if err != nil {
				return fmt.Errorf(`failed to read value for key %q: %w`, fieldName, err)
			}
			if err := json.Unmarshal(raw, &v); err != nil {
				return fmt.Errorf(`failed to decode value for key %q: %w`, fieldName, err)
			}
			s.privateParams[fieldName] = v
		}
	}
	// consume closing '}'
	if _, err := dec.ReadToken(); err != nil {
		return fmt.Errorf(`error reading closing token: %w`, err)
	}

	// This is really silly, but we can only detect the
	// lack of the "keys" field after going through the
	// entire object once
	// Not checking for len(s.keys) == 0, because it could be
	// an empty key set
	if !sawKeysField {
		key, err := doParseKey(data, options...)
		if err != nil {
			return fmt.Errorf(`failed to parse sole key in key set: %w`, err)
		}
		s.keys = append(s.keys, key)
	}
	return nil
}

func (s *set) LookupKeyID(kid string) (Key, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, key := range s.keys {
		gotkid, ok := key.KeyID()
		if ok && gotkid == kid {
			return key, true
		}
	}
	return nil, false
}

func (s *set) All() iter.Seq2[int, Key] {
	return func(yield func(int, Key) bool) {
		s.mu.RLock()
		defer s.mu.RUnlock()
		for i, k := range s.keys {
			if !yield(i, k) {
				return
			}
		}
	}
}

func (s *set) Fields() iter.Seq2[string, any] {
	return func(yield func(string, any) bool) {
		s.mu.RLock()
		defer s.mu.RUnlock()
		for k, v := range s.privateParams {
			if !yield(k, v) {
				return
			}
		}
	}
}

func (s *set) DecodeCtx() DecodeCtx {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dc
}

func (s *set) SetDecodeCtx(dc DecodeCtx) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dc = dc
}

func (s *set) Clone() (Set, error) {
	s2 := newSet()

	s.mu.RLock()
	defer s.mu.RUnlock()

	s2.keys = make([]Key, len(s.keys))
	copy(s2.keys, s.keys)

	maps.Copy(s2.privateParams, s.privateParams)

	return s2, nil
}
