// Code generated by tools/cmd/genjwa/main.go. DO NOT EDIT.

package jwa

import (
	"fmt"
	"sort"
	"sync"
)

// KeyEncryptionAlgorithm represents the various encryption algorithms as described in https://tools.ietf.org/html/rfc7518#section-4.1
type KeyEncryptionAlgorithm string

// Supported values for KeyEncryptionAlgorithm
const (
	A128GCMKW          KeyEncryptionAlgorithm = "A128GCMKW"          // AES-GCM key wrap (128)
	A128KW             KeyEncryptionAlgorithm = "A128KW"             // AES key wrap (128)
	A192GCMKW          KeyEncryptionAlgorithm = "A192GCMKW"          // AES-GCM key wrap (192)
	A192KW             KeyEncryptionAlgorithm = "A192KW"             // AES key wrap (192)
	A256GCMKW          KeyEncryptionAlgorithm = "A256GCMKW"          // AES-GCM key wrap (256)
	A256KW             KeyEncryptionAlgorithm = "A256KW"             // AES key wrap (256)
	DIRECT             KeyEncryptionAlgorithm = "dir"                // Direct encryption
	ECDH_ES            KeyEncryptionAlgorithm = "ECDH-ES"            // ECDH-ES
	ECDH_ES_A128KW     KeyEncryptionAlgorithm = "ECDH-ES+A128KW"     // ECDH-ES + AES key wrap (128)
	ECDH_ES_A192KW     KeyEncryptionAlgorithm = "ECDH-ES+A192KW"     // ECDH-ES + AES key wrap (192)
	ECDH_ES_A256KW     KeyEncryptionAlgorithm = "ECDH-ES+A256KW"     // ECDH-ES + AES key wrap (256)
	PBES2_HS256_A128KW KeyEncryptionAlgorithm = "PBES2-HS256+A128KW" // PBES2 + HMAC-SHA256 + AES key wrap (128)
	PBES2_HS384_A192KW KeyEncryptionAlgorithm = "PBES2-HS384+A192KW" // PBES2 + HMAC-SHA384 + AES key wrap (192)
	PBES2_HS512_A256KW KeyEncryptionAlgorithm = "PBES2-HS512+A256KW" // PBES2 + HMAC-SHA512 + AES key wrap (256)
	RSA1_5             KeyEncryptionAlgorithm = "RSA1_5"             // RSA-PKCS1v1.5
	RSA_OAEP           KeyEncryptionAlgorithm = "RSA-OAEP"           // RSA-OAEP-SHA1
	RSA_OAEP_256       KeyEncryptionAlgorithm = "RSA-OAEP-256"       // RSA-OAEP-SHA256
	RSA_OAEP_384       KeyEncryptionAlgorithm = "RSA-OAEP-384"       // RSA-OAEP-SHA384
	RSA_OAEP_512       KeyEncryptionAlgorithm = "RSA-OAEP-512"       // RSA-OAEP-SHA512
)

var muKeyEncryptionAlgorithms sync.RWMutex
var allKeyEncryptionAlgorithms map[KeyEncryptionAlgorithm]struct{}
var listKeyEncryptionAlgorithm []KeyEncryptionAlgorithm
var symmetricKeyEncryptionAlgorithms map[KeyEncryptionAlgorithm]struct{}

func init() {
	muKeyEncryptionAlgorithms.Lock()
	defer muKeyEncryptionAlgorithms.Unlock()
	allKeyEncryptionAlgorithms = make(map[KeyEncryptionAlgorithm]struct{})
	allKeyEncryptionAlgorithms[A128GCMKW] = struct{}{}
	allKeyEncryptionAlgorithms[A128KW] = struct{}{}
	allKeyEncryptionAlgorithms[A192GCMKW] = struct{}{}
	allKeyEncryptionAlgorithms[A192KW] = struct{}{}
	allKeyEncryptionAlgorithms[A256GCMKW] = struct{}{}
	allKeyEncryptionAlgorithms[A256KW] = struct{}{}
	allKeyEncryptionAlgorithms[DIRECT] = struct{}{}
	allKeyEncryptionAlgorithms[ECDH_ES] = struct{}{}
	allKeyEncryptionAlgorithms[ECDH_ES_A128KW] = struct{}{}
	allKeyEncryptionAlgorithms[ECDH_ES_A192KW] = struct{}{}
	allKeyEncryptionAlgorithms[ECDH_ES_A256KW] = struct{}{}
	allKeyEncryptionAlgorithms[PBES2_HS256_A128KW] = struct{}{}
	allKeyEncryptionAlgorithms[PBES2_HS384_A192KW] = struct{}{}
	allKeyEncryptionAlgorithms[PBES2_HS512_A256KW] = struct{}{}
	allKeyEncryptionAlgorithms[RSA1_5] = struct{}{}
	allKeyEncryptionAlgorithms[RSA_OAEP] = struct{}{}
	allKeyEncryptionAlgorithms[RSA_OAEP_256] = struct{}{}
	allKeyEncryptionAlgorithms[RSA_OAEP_384] = struct{}{}
	allKeyEncryptionAlgorithms[RSA_OAEP_512] = struct{}{}
	symmetricKeyEncryptionAlgorithms = make(map[KeyEncryptionAlgorithm]struct{})
	symmetricKeyEncryptionAlgorithms[A128GCMKW] = struct{}{}
	symmetricKeyEncryptionAlgorithms[A128KW] = struct{}{}
	symmetricKeyEncryptionAlgorithms[A192GCMKW] = struct{}{}
	symmetricKeyEncryptionAlgorithms[A192KW] = struct{}{}
	symmetricKeyEncryptionAlgorithms[A256GCMKW] = struct{}{}
	symmetricKeyEncryptionAlgorithms[A256KW] = struct{}{}
	symmetricKeyEncryptionAlgorithms[DIRECT] = struct{}{}
	symmetricKeyEncryptionAlgorithms[PBES2_HS256_A128KW] = struct{}{}
	symmetricKeyEncryptionAlgorithms[PBES2_HS384_A192KW] = struct{}{}
	symmetricKeyEncryptionAlgorithms[PBES2_HS512_A256KW] = struct{}{}
	rebuildKeyEncryptionAlgorithm()
}

// RegisterKeyEncryptionAlgorithm registers a new KeyEncryptionAlgorithm so that the jwx can properly handle the new value.
// Duplicates will silently be ignored
func RegisterKeyEncryptionAlgorithm(v KeyEncryptionAlgorithm) {
	RegisterKeyEncryptionAlgorithmWithOptions(v)
}

// RegisterKeyEncryptionAlgorithmWithOptions is the same as RegisterKeyEncryptionAlgorithm when used without options,
// but allows its behavior to change based on the provided options.
// This is an experimental AND stopgap function which will most likely be merged in RegisterKeyEncryptionAlgorithm, and subsequently removed in the future. As such it should not be considered part of the stable API -- it is still subject to change.
//
// You can pass `WithSymmetricAlgorithm(true)` to let the library know that it's a symmetric algorithm. This library makes no attempt to verify if the algorithm is indeed symmetric or not.
func RegisterKeyEncryptionAlgorithmWithOptions(v KeyEncryptionAlgorithm, options ...RegisterAlgorithmOption) {
	var symmetric bool
	//nolint:forcetypeassert
	for _, option := range options {
		switch option.Ident() {
		case identSymmetricAlgorithm{}:
			symmetric = option.Value().(bool)
		}
	}
	muKeyEncryptionAlgorithms.Lock()
	defer muKeyEncryptionAlgorithms.Unlock()
	if _, ok := allKeyEncryptionAlgorithms[v]; !ok {
		allKeyEncryptionAlgorithms[v] = struct{}{}
		if symmetric {
			symmetricKeyEncryptionAlgorithms[v] = struct{}{}
		}
		rebuildKeyEncryptionAlgorithm()
	}
}

// UnregisterKeyEncryptionAlgorithm unregisters a KeyEncryptionAlgorithm from its known database.
// Non-existent entries will silently be ignored
func UnregisterKeyEncryptionAlgorithm(v KeyEncryptionAlgorithm) {
	muKeyEncryptionAlgorithms.Lock()
	defer muKeyEncryptionAlgorithms.Unlock()
	if _, ok := allKeyEncryptionAlgorithms[v]; ok {
		delete(allKeyEncryptionAlgorithms, v)
		if _, ok := symmetricKeyEncryptionAlgorithms[v]; ok {
			delete(symmetricKeyEncryptionAlgorithms, v)
		}
		rebuildKeyEncryptionAlgorithm()
	}
}

func rebuildKeyEncryptionAlgorithm() {
	listKeyEncryptionAlgorithm = make([]KeyEncryptionAlgorithm, 0, len(allKeyEncryptionAlgorithms))
	for v := range allKeyEncryptionAlgorithms {
		listKeyEncryptionAlgorithm = append(listKeyEncryptionAlgorithm, v)
	}
	sort.Slice(listKeyEncryptionAlgorithm, func(i, j int) bool {
		return string(listKeyEncryptionAlgorithm[i]) < string(listKeyEncryptionAlgorithm[j])
	})
}

// KeyEncryptionAlgorithms returns a list of all available values for KeyEncryptionAlgorithm
func KeyEncryptionAlgorithms() []KeyEncryptionAlgorithm {
	muKeyEncryptionAlgorithms.RLock()
	defer muKeyEncryptionAlgorithms.RUnlock()
	return listKeyEncryptionAlgorithm
}

// Accept is used when conversion from values given by
// outside sources (such as JSON payloads) is required
func (v *KeyEncryptionAlgorithm) Accept(value interface{}) error {
	var tmp KeyEncryptionAlgorithm
	if x, ok := value.(KeyEncryptionAlgorithm); ok {
		tmp = x
	} else {
		var s string
		switch x := value.(type) {
		case fmt.Stringer:
			s = x.String()
		case string:
			s = x
		default:
			return fmt.Errorf(`invalid type for jwa.KeyEncryptionAlgorithm: %T`, value)
		}
		tmp = KeyEncryptionAlgorithm(s)
	}
	if _, ok := allKeyEncryptionAlgorithms[tmp]; !ok {
		return fmt.Errorf(`invalid jwa.KeyEncryptionAlgorithm value`)
	}

	*v = tmp
	return nil
}

// String returns the string representation of a KeyEncryptionAlgorithm
func (v KeyEncryptionAlgorithm) String() string {
	return string(v)
}

// IsSymmetric returns true if the algorithm is a symmetric type.
func (v KeyEncryptionAlgorithm) IsSymmetric() bool {
	_, ok := symmetricKeyEncryptionAlgorithms[v]
	return ok
}
