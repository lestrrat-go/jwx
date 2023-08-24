package jwk

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"sync"

	"github.com/lestrrat-go/jwx/v2/x25519"
)

type RawFromKeyer interface {
	RawFromKey(Key, interface{}) error
}

type ChainedRawFromKeyer interface {
	Next(RawFromKeyer, Key, interface{}) error
}

type ChainedRawFromKeyFunc func(RawFromKeyer, Key, interface{}) error

func (fn ChainedRawFromKeyFunc) Next(n RawFromKeyer, key Key, raw interface{}) error {
	return fn(n, key, raw)
}

type chainedRawFromKey struct {
	mu   sync.RWMutex
	list []ChainedRawFromKeyer
}

type chainedRawFromKeyCallState struct {
	current int
	parent  *chainedRawFromKey
}

func (c *chainedRawFromKey) Add(rfk ChainedRawFromKeyer) {
	if rfk == nil {
		return // no-op
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.list = append(c.list, rfk)
}

func (c *chainedRawFromKey) Next(key Key, raw interface{}) error {
	c.mu.RLock()
	lrfk := len(c.list)
	c.mu.RUnlock()
	st := &chainedRawFromKeyCallState{parent: c, current: lrfk}
	return st.RawFromKey(key, raw)
}

func (s *chainedRawFromKeyCallState) RawFromKey(key Key, raw interface{}) error {
	idx := s.current - 1

	s.parent.mu.RLock()
	defer s.parent.mu.RUnlock()

	llist := len(s.parent.list)
	if idx < 0 || idx >= llist {
		return fmt.Errorf(`jwk.Raw: invalid raw key type %T`, raw)
	}
	s.current = idx

	rfk := s.parent.list[idx]
	return rfk.Next(s, key, raw)
}

type chainedKeyFromRaw struct {
	mu   sync.RWMutex
	list []ChainedKeyFromRawer
}

type chainedKeyFromRawCallState struct {
	current int
	parent  *chainedKeyFromRaw
}

func (c *chainedKeyFromRaw) Add(kfr ChainedKeyFromRawer) {
	if kfr == nil {
		return // no-op
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.list = append(c.list, kfr)
}

func (c *chainedKeyFromRaw) Next(raw interface{}) (Key, error) {
	c.mu.RLock()
	lkfr := len(c.list)
	c.mu.RUnlock()
	st := &chainedKeyFromRawCallState{parent: c, current: lkfr}
	return st.KeyFromRaw(raw)
}

func (s *chainedKeyFromRawCallState) KeyFromRaw(raw interface{}) (Key, error) {
	idx := s.current - 1

	s.parent.mu.RLock()
	defer s.parent.mu.RUnlock()

	llist := len(s.parent.list)
	if idx < 0 || idx >= llist {
		return nil, fmt.Errorf(`jwk.FromRaw: invalid raw key type %T`, raw)
	}
	s.current = idx

	kfr := s.parent.list[idx]
	return kfr.Next(s, raw)
}

var chainedKFR = &chainedKeyFromRaw{
	list: []ChainedKeyFromRawer{ChainedKeyFromRawFunc(fromRaw)},
}

var chainedRFK = &chainedRawFromKey{
	list: []ChainedRawFromKeyer{ChainedRawFromKeyFunc(toRaw)},
}

type KeyFromRawer interface {
	KeyFromRaw(interface{}) (Key, error)
}

// ChainedKeyFromRawer describes a type that can build a Key from a raw key
//
// ChainedKeyFromRawer objects are expected to be called in sequence. When a new
// object is added to the list of KeyFromRawer objects, they are called
// from the most recently added all the way up to the default object,
// if you choose to do so by invokind the first argument.
type ChainedKeyFromRawer interface {
	// Next calls the handler in the subsequent chain of handlers.
	//
	// The first argument invokes the _next_ KeyFromRawer that can be called in the
	// chain of possible KeyFromRawers that are registered. For example,
	// if your KeyFromRawer failed to match any key type that you can handle,
	// you can defer to the next KeyFromRawer to see if it can handle it
	Next(KeyFromRawer, interface{}) (Key, error)
}

// ChainedKeyFromRawFunc is an instance of ChainedKeyFromRawer represented by a function
type ChainedKeyFromRawFunc func(KeyFromRawer, interface{}) (Key, error)

func (fn ChainedKeyFromRawFunc) Next(n KeyFromRawer, raw interface{}) (Key, error) {
	return fn(n, raw)
}

// AddKeyFromRaw adds a new KeyFromRawer object that is used in the FromRaw() function, which
// in turn will handle converting a raw key to a Key.
func AddKeyFromRaw(kfr ChainedKeyFromRawer) {
	chainedKFR.Add(kfr)
}

func fromRaw(_ KeyFromRawer, key interface{}) (Key, error) {
	var ptr interface{}
	switch v := key.(type) {
	case rsa.PrivateKey:
		ptr = &v
	case rsa.PublicKey:
		ptr = &v
	case ecdsa.PrivateKey:
		ptr = &v
	case ecdsa.PublicKey:
		ptr = &v
	default:
		ptr = v
	}

	switch rawKey := ptr.(type) {
	case *rsa.PrivateKey:
		k := newRSAPrivateKey()
		if err := k.FromRaw(rawKey); err != nil {
			return nil, fmt.Errorf(`failed to initialize %T from %T: %w`, k, rawKey, err)
		}
		return k, nil
	case *rsa.PublicKey:
		k := newRSAPublicKey()
		if err := k.FromRaw(rawKey); err != nil {
			return nil, fmt.Errorf(`failed to initialize %T from %T: %w`, k, rawKey, err)
		}
		return k, nil
	case *ecdsa.PrivateKey:
		k := newECDSAPrivateKey()
		if err := k.FromRaw(rawKey); err != nil {
			return nil, fmt.Errorf(`failed to initialize %T from %T: %w`, k, rawKey, err)
		}
		return k, nil
	case *ecdsa.PublicKey:
		k := newECDSAPublicKey()
		if err := k.FromRaw(rawKey); err != nil {
			return nil, fmt.Errorf(`failed to initialize %T from %T: %w`, k, rawKey, err)
		}
		return k, nil
	case ed25519.PrivateKey:
		k := newOKPPrivateKey()
		if err := k.FromRaw(rawKey); err != nil {
			return nil, fmt.Errorf(`failed to initialize %T from %T: %w`, k, rawKey, err)
		}
		return k, nil
	case ed25519.PublicKey:
		k := newOKPPublicKey()
		if err := k.FromRaw(rawKey); err != nil {
			return nil, fmt.Errorf(`failed to initialize %T from %T: %w`, k, rawKey, err)
		}
		return k, nil
	case x25519.PrivateKey:
		k := newOKPPrivateKey()
		if err := k.FromRaw(rawKey); err != nil {
			return nil, fmt.Errorf(`failed to initialize %T from %T: %w`, k, rawKey, err)
		}
		return k, nil
	case x25519.PublicKey:
		k := newOKPPublicKey()
		if err := k.FromRaw(rawKey); err != nil {
			return nil, fmt.Errorf(`failed to initialize %T from %T: %w`, k, rawKey, err)
		}
		return k, nil
	case []byte:
		k := newSymmetricKey()
		if err := k.FromRaw(rawKey); err != nil {
			return nil, fmt.Errorf(`failed to initialize %T from %T: %w`, k, rawKey, err)
		}
		return k, nil
	default:
		return nil, fmt.Errorf(`invalid key type '%T' for jwk.FromRaw`, key)
	}
}

// FromRaw creates a Key from the given key (RSA/ECDSA/symmetric keys).
//
// The constructor auto-detects the type of key to be instantiated
// based on the input type:
//
//   - "crypto/rsa".PrivateKey and "crypto/rsa".PublicKey creates an RSA based key
//   - "crypto/ecdsa".PrivateKey and "crypto/ecdsa".PublicKey creates an EC based key
//   - "crypto/ed25519".PrivateKey and "crypto/ed25519".PublicKey creates an OKP based key
//   - []byte creates a symmetric key
//
// This function also takes care of additional key types added by external
// libraries such as secp256k1 keys.
func FromRaw(raw interface{}) (Key, error) {
	if raw == nil {
		return nil, fmt.Errorf(`jwk.FromRaw requires a non-nil key`)
	}

	return chainedKFR.Next(raw)
}

// Raw converts a jwk.Key to its raw form and stores in the `raw` variable.
// `raw` must be a pointer to a compatible object, otherwise an error will
// be returned.
//
// As of v2.0.12, it is recommended to use `jwk.Raw()` instead of `keyObject.Raw()`.
// The latter will NOT take care of converting additional key types added by
// external libraries, such as secp256k1 keys.
func Raw(key Key, raw interface{}) error {
	return chainedRFK.Next(key, raw)
}

func toRaw(_ RawFromKeyer, key Key, raw interface{}) error {
	return key.Raw(raw)
}

func AddRawFromKey(rfk ChainedRawFromKeyer) {
	chainedRFK.Add(rfk)
}
