// Code generated by tools/cmd/genjwa/main.go. DO NOT EDIT.

package jwa

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// KeyType represents the key type ("kty") that are supported
type KeyType string

// Supported values for KeyType
const (
	EC             KeyType = "EC"  // Elliptic Curve
	InvalidKeyType KeyType = ""    // Invalid KeyType
	OKP            KeyType = "OKP" // Octet string key pairs
	OctetSeq       KeyType = "oct" // Octet sequence (used to represent symmetric keys)
	RSA            KeyType = "RSA" // RSA
)

var muKeyTypes sync.RWMutex
var allKeyTypes map[KeyType]struct{}
var listKeyType []KeyType

func init() {
	muKeyTypes.Lock()
	defer muKeyTypes.Unlock()
	allKeyTypes = make(map[KeyType]struct{})
	allKeyTypes[EC] = struct{}{}
	allKeyTypes[OKP] = struct{}{}
	allKeyTypes[OctetSeq] = struct{}{}
	allKeyTypes[RSA] = struct{}{}
	rebuildKeyType()
}

// RegisterKeyType registers a new KeyType so that the jwx can properly handle the new value.
// Duplicates will silently be ignored
func RegisterKeyType(v KeyType) {
	muKeyTypes.Lock()
	defer muKeyTypes.Unlock()
	if _, ok := allKeyTypes[v]; !ok {
		allKeyTypes[v] = struct{}{}
		rebuildKeyType()
	}
}

// RegisterKeyTypeWithOptions is the same as RegisterKeyType when used without options,
// but allows its behavior to change based on the provided options.
// E.g. you can pass `WithSymmetricAlgorithm(true)` to let the library know that it's a symmetric algorithm.
// Errors can occur because of the options, so this function also returns an error.
func RegisterKeyTypeWithOptions(v KeyType, options ...RegisterAlgorithmOption) error {
	//nolint:forcetypeassert
	for _, option := range options {
		switch option.Ident() {
		default:
			return fmt.Errorf("invalid jwa.RegisterAlgorithmOption %q passed", "With"+strings.TrimPrefix(fmt.Sprintf("%T", option.Ident()), "jwa.ident"))
		}
	}
	muKeyTypes.Lock()
	defer muKeyTypes.Unlock()
	if _, ok := allKeyTypes[v]; !ok {
		allKeyTypes[v] = struct{}{}
		rebuildKeyType()
	}
	return nil
}

// UnregisterKeyType unregisters a KeyType from its known database.
// Non-existentn entries will silently be ignored
func UnregisterKeyType(v KeyType) {
	muKeyTypes.Lock()
	defer muKeyTypes.Unlock()
	if _, ok := allKeyTypes[v]; ok {
		delete(allKeyTypes, v)
		rebuildKeyType()
	}
}

func rebuildKeyType() {
	listKeyType = make([]KeyType, 0, len(allKeyTypes))
	for v := range allKeyTypes {
		listKeyType = append(listKeyType, v)
	}
	sort.Slice(listKeyType, func(i, j int) bool {
		return string(listKeyType[i]) < string(listKeyType[j])
	})
}

// KeyTypes returns a list of all available values for KeyType
func KeyTypes() []KeyType {
	muKeyTypes.RLock()
	defer muKeyTypes.RUnlock()
	return listKeyType
}

// Accept is used when conversion from values given by
// outside sources (such as JSON payloads) is required
func (v *KeyType) Accept(value interface{}) error {
	var tmp KeyType
	if x, ok := value.(KeyType); ok {
		tmp = x
	} else {
		var s string
		switch x := value.(type) {
		case fmt.Stringer:
			s = x.String()
		case string:
			s = x
		default:
			return fmt.Errorf(`invalid type for jwa.KeyType: %T`, value)
		}
		tmp = KeyType(s)
	}
	if _, ok := allKeyTypes[tmp]; !ok {
		return fmt.Errorf(`invalid jwa.KeyType value`)
	}

	*v = tmp
	return nil
}

// String returns the string representation of a KeyType
func (v KeyType) String() string {
	return string(v)
}
