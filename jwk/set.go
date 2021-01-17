package jwk

import (
	"context"

	"github.com/lestrrat-go/iter/arrayiter"
	"github.com/lestrrat-go/jwx/internal/json"
	"github.com/pkg/errors"
)

func NewSet() Set {
	return &set{}
}

// Get returns the key at index `idx`. If the index is out of range,
// then the second return value is false.
func (s *set) Get(idx int) (Key, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if idx >= 0 && idx < s.Len() {
		return s.keys[idx], true
	}
	return nil, false
}

// Len returns the number of keys in this set
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

// Index returns the index where the given key exists, -1 otherwise
func (s *set) Index(key Key) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.indexNL(key)
}

// Add adds the specified key. If the key already exists in the set, it is
// not added.
func (s *set) Add(key Key) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if i := s.indexNL(key); i > -1 {
		return false
	}
	s.keys = append(s.keys, key)
	return true
}

// Remove removes the key from the set.
func (s *set) Remove(key Key) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, k := range s.keys {
		if k == key {
			switch i {
			case 0:
				s.keys = s.keys[1:]
			case len(s.keys) - 1:
				s.keys = s.keys[:i-1]
			default:
				s.keys = append(s.keys[:i-1], s.keys[i+1:]...)
			}
			return true
		}
	}
	return false
}

// Clear resets the list of keys associated with this set.
func (s *set) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.keys = nil
}

// Iterate creates an iterator to iterate through all keys in the set
func (s *set) Iterate(ctx context.Context) KeyIterator {
	ch := make(chan *KeyPair, s.Len())
	go iterate(ctx, s.keys, ch)
	return arrayiter.New(ch)
}

func iterate(ctx context.Context, keys []Key, ch chan *KeyPair) {
	defer close(ch)

	for i, key := range keys {
		pair := &KeyPair{Index: i, Value: key}
		select {
		case <-ctx.Done():
			return
		case ch <- pair:
		}
	}
}

type keySetMarshalProxy struct {
	Keys []json.RawMessage `json:"keys"`
}

func (s *set) MarshalJSON() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// no need to lock, as we're getting a copy (s Set)
	var proxy keySetMarshalProxy
	proxy.Keys = make([]json.RawMessage, len(s.keys))
	for i, k := range s.keys {
		buf, err := json.Marshal(k)
		if err != nil {
			return nil, errors.Wrapf(err, `failed to marshal key #%d`, i)
		}
		proxy.Keys[i] = buf
	}
	return json.Marshal(proxy)
}

func (s *set) UnmarshalJSON(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var proxy keySetMarshalProxy
	if err := json.Unmarshal(data, &proxy); err != nil {
		return errors.Wrap(err, `failed to unmarshal into Key (proxy)`)
	}

	if len(proxy.Keys) == 0 {
		k, err := ParseKey(data)
		if err != nil {
			return errors.Wrap(err, `failed to unmarshal key from JSON headers`)
		}
		s.keys = append(s.keys, k)
	} else {
		for i, buf := range proxy.Keys {
			k, err := ParseKey([]byte(buf))
			if err != nil {
				return errors.Wrapf(err, `failed to unmarshal key #%d (total %d) from multi-key JWK set`, i+1, len(proxy.Keys))
			}
			s.keys = append(s.keys, k)
		}
	}
	return nil
}

// LookupKeyID returns the first for key matching the given key id.
// The second return value is false if there are not keys matching the key id.
// The set *may* contain multiple keys with the same key id. If you
// need all of them, use `Iterate()`
func (s *set) LookupKeyID(kid string) (Key, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for iter := s.Iterate(context.TODO()); iter.Next(context.TODO()); {
		pair := iter.Pair()
		key := pair.Value.(Key)
		if key.KeyID() == kid {
			return key, true
		}
	}
	return nil, false
}
