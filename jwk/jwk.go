//go:generate ../tools/cmd/genjwk.sh

// Package jwk implements JWK as described in https://tools.ietf.org/html/rfc7517
package jwk

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"sync"

	"github.com/lestrrat-go/blackmagic"
	"github.com/lestrrat-go/jwx/v3/internal/base64"
	"github.com/lestrrat-go/jwx/v3/internal/json"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/x25519"
)

var registry = json.NewRegistry()

func bigIntToBytes(n *big.Int) ([]byte, error) {
	if n == nil {
		return nil, fmt.Errorf(`invalid *big.Int value`)
	}
	return n.Bytes(), nil
}

func init() {
	if err := RegisterProbeField(reflect.StructField{
		Name: "Kty",
		Type: reflect.TypeOf(""),
		Tag:  `json:"kty"`,
	}); err != nil {
		panic(fmt.Errorf("failed to register mandatory probe for 'kty' field: %w", err))
	}
	if err := RegisterProbeField(reflect.StructField{
		Name: "D",
		Type: reflect.TypeOf(json.RawMessage(nil)),
		Tag:  `json:"d,omitempty"`,
	}); err != nil {
		panic(fmt.Errorf("failed to register mandatory probe for 'kty' field: %w", err))
	}
}

// keyProber is the object that starts the probing. When Probe() is called,
// it creates (possibly from a cached value) an object that is used to
// hold hint values.
type keyProber struct {
	mu     sync.RWMutex
	pool   *sync.Pool
	fields map[string]reflect.StructField
	typ    reflect.Type
}

func (kp *keyProber) AddField(field reflect.StructField) error {
	kp.mu.Lock()
	defer kp.mu.Unlock()

	if _, ok := kp.fields[field.Name]; ok {
		return fmt.Errorf(`field name %s is already registered`, field.Name)
	}
	kp.fields[field.Name] = field
	kp.makeStructType()

	// Update pool (note: the logic is the same, but we need to recreate it
	// so that we don't accidentally use old stored values)
	kp.pool = &sync.Pool{
		New: kp.makeStruct,
	}
	return nil
}

func (kp *keyProber) makeStructType() {
	// DOES NOT LOCK
	fields := make([]reflect.StructField, 0, len(kp.fields))
	for _, f := range kp.fields {
		fields = append(fields, f)
	}
	kp.typ = reflect.StructOf(fields)
}

func (kp *keyProber) makeStruct() interface{} {
	return reflect.New(kp.typ)
}

func (kp *keyProber) Probe(data []byte) (*KeyProbe, error) {
	kp.mu.RLock()
	defer kp.mu.RUnlock()

	// if the field list unchanged, so is the pool object, so effectively
	// we should be using the cached version
	v := kp.pool.Get()
	if v == nil {
		return nil, fmt.Errorf(`probe: failed to get object from pool`)
	}
	rv, ok := v.(reflect.Value)
	if !ok {
		return nil, fmt.Errorf(`probe: value returned from pool as of type %T, expected reflect.Value`, v)
	}

	if err := json.Unmarshal(data, rv.Interface()); err != nil {
		return nil, fmt.Errorf(`probe: failed to unmarshal data: %w`, err)
	}

	return &KeyProbe{data: rv}, nil
}

// KeyProbe is the object that carries the hints when parsing a key.
// The exact list of fields can vary depending on the types of key
// that are registered.
//
// Use `Get()` to access the value of a field.
//
// The underlying data stored in a KeyProbe is recycled each
// time a value is parsed, therefore you are not allowed to hold
// onto this object after ParseKey() is done.
type KeyProbe struct {
	data reflect.Value
}

// Get returns the value of the field with the given `name“.
// `dst` must be a pointer to a value that can hold the type of
// the value of the field, which is determined by the
// field type registered through `jwk.RegisterProbeField()`
func (kp *KeyProbe) Get(name string, dst interface{}) error {
	f := kp.data.Elem().FieldByName(name)
	if !f.IsValid() {
		return fmt.Errorf(`field %s not found`, name)
	}

	if err := blackmagic.AssignIfCompatible(dst, f.Addr().Interface()); err != nil {
		return fmt.Errorf(`failed to assign value of field %q to %T: %w`, name, dst, err)
	}
	return nil
}

// We don't really need the object, we need to know its type
var keyProbe = &keyProber{
	fields: make(map[string]reflect.StructField),
}

// RegisterProbeField adds a new field to be probed during the initial
// phase of parsing. This is done by partially parsing the JSON payload,
// and we do this by calling `json.Unmarshal` using a dynamic type that
// can possibly be modified during runtime. This function is used to
// add a new field to this dynamic type.
//
// Note that the `Name` field for the given `reflect.StructField` must start
// with an upper case alphabet, such that it is treated as an exported field.
// So for example, if you want to probe the "my_hint" field, you should specify
// the field name as "MyHint" or similar.
//
// Also the field name must be unique. If you believe that your field name may
// collide with other packages that may want to add their own probes,
// it is the responsibility of the caller
// to ensure that the field name is unique (possibly by prefixing the field
// name with a unique string). It is important to note that the field name
// need not be the same as the JSON field name. For example, your field name
// could be "MyPkg_MyHint", while the actual JSON field name could be "my_hint".
//
// If the field name is not unique, an error is returned.
func RegisterProbeField(p reflect.StructField) error {
	// locking is done inside keyProbe
	return keyProbe.AddField(p)
}

// KeyUnmarshaler is a thin wrapper around json.Unmarshal. It behaves almost
// exactly like json.Unmarshal, but it allows us to add extra magic that
// is specific to this library before calling the actual json.Unmarshal.
type KeyUnmarshaler interface {
	UnmarshalKey(data []byte, key interface{}) error
}

// # Registering a key type
//
// You can add the ability to use a JWK that this library does not
// implement out of the box. You can do this by registering your own
// KeyParser instance.
//
//  func init() {
//    // optional
//    jwk.RegiserProbeField(reflect.StructField{Name: "SomeHint", Type: reflect.TypeOf(""), Tag: `json:"some_hint"`})
//    jwk.RegisterKeyParser(&MyKeyParser{})
//  }
//
// In order to understand how this works, you need to understand
// how the `jwk.ParseKey()` works.
//
// The first thing that occurs when parsing a key is a partial
// unmarshaling of the payload into a hint / probe object.
//
// Because the `json.Unmarshal` works by calling the `UnmarshalJSON`
// method on a concrete object, we need to create one first. In order
// to create the appropriate Go object, we need to peek into the
// payload and figure out what type of key it is.
//
// In order to do this, we create a new KeyProber to partially populate
// the object with hints from the payload. For example, a JWK representing
// an RSA key would look like:
//
//  { "kty": "RSA", "n": ..., "e": ..., ... }
//
// Therefore, a KeyProbe that can unmarshal the value of the field "kty"
// would be able to tell us that this is an RSA key.
//
// Also, if said payload contains some value in the "d" field, we can
// also tell that this is a private key, as only private keys need
// this field.
//
// For most cases, the default KeyProbe implementation should be sufficient.
// You would be able to query "kty" and "d" fields via the `Get()` method.
//
//  var kty string
//  _ = probe.Get("Kty", &kty)
//
// However, if you need extra pieces of information, you can specify
// additional fields to be probed. For example, if you want to know the
// value of the field "my_hint" (which holds a string value) from the payload,
// you can register it to be probed by registering an additional probe field like this:
//
//  jwk.RegisterProbeField(reflect.StructField{Name: "MyHint", Type: reflect.TypeOf(""), Tag: `json:"my_hint"`})
//
// Once the probe is done, the library will iterate over the registered parsers
// and attempt to parse the key by calling their `ParseKey()` methods.
// The parsers will be called in reverse order that they were registered.
// This means that it will try all parsers that were registered by third
// parties, and once those are exhausted, the default parser will be used.
//
// Each parser's `ParseKey()`` method will receive three arguments: the probe object, a
// KeyUnmarshaler, and the raw payload. The probe object can be used
// as a hint to determine what kind of key to instantiate. An example
// pseudocode may look like this:
//
//  var kty string
//  _ = probe.Get("Kty", &kty)
//  switch kty {
//  case "RSA":
//    // create an RSA key
//  case "EC":
//    // create an EC key
//  ...
//  }
//
// The `KeyUnmarshaler` is a thin wrapper around `json.Unmarshal` it
// works almost identical to `json.Unmarshal`, but it allows us to
// add extra magic that is specific to this library before calling
// the actual `json.Unmarshal`. If you want to try to unmarshal the
// payload, please use this instead of `json.Unmarshal`.
//
//  func init() {
//    jwk.RegisterFieldProbe(reflect.StructField{Name: "MyHint", Type: reflect.TypeOf(""), Tag: `json:"my_hint"`})
//    jwk.RegisterParser(&MyKeyParser{})
//  }
//
//  type MyKeyParser struct { ... }
//  func(*MyKeyParser) ParseKey(rawProbe *KeyProbe, unmarshaler KeyUnmarshaler, data []byte) (jwk.Key, error) {
//    // Create concrete type
//    var hint string
//    if err := probe.Get("MyHint", &hint); err != nil {
//       // if it doesn't have the `my_hint` field, it probably means
//       // it's not for us, so we return ContinueParseError so that
//       // the next parser can pick it up
//       return nil, jwk.ContinueParseError()
//    }
//
//    // Use hint to determine concrete key type
//    var key jwk.Key
//    switch hint {
//    case ...:
//     key = = myNewAwesomeJWK()
//    ...
//
//    return unmarshaler.Unmarshal(data, key)
//  }
//
// This functionality should be considered experimental. While we
// expect that the functionality itself will remain, the API may
// change in backward incompatible ways, even during minor version
// releases.

var cpe = &continueParseError{}

// ContinueParseError returns an opaque error that can be returned
// when a `KeyParser` cannot parse the given payload, but would like
// the parsing process to continue with the next parser.
func ContinueParseError() error {
	return cpe
}

type continueParseError struct{}

func (e *continueParseError) Error() string {
	return "continue parsing"
}

func IsContiueParseError(err error) bool {
	return errors.Is(err, &continueParseError{})
}

// KeyParser represents a type that can parse a []byte into a jwk.Key.
type KeyParser interface {
	// ParseKey parses a JSON payload to a `jwk.Key` object. The first
	// argument is an object that contains some hints as to what kind of
	// key the JSON payload contains.
	//
	// If your KeyParser decides that the payload is not something
	// you can parse, and you would like to continue parsing with
	// the remaining KeyParser instances that are registered,
	// return a `jwk.ContinueParseError`. Any other errors will immediately
	// halt the parsing process.
	//
	// When unmarshaling JSON, use the unmarshaler object supplied as
	// the second argument. This will ensure that the JSON is unmarshaled
	// in a way that is compatible with the rest of the library.
	ParseKey(probe *KeyProbe, unmarshaler KeyUnmarshaler, payload []byte) (Key, error)
}

// KeyParseFunc is a type of KeyParser that is based on a function/closure
type KeyParseFunc func(probe *KeyProbe, unmarshaler KeyUnmarshaler, payload []byte) (Key, error)

func (f KeyParseFunc) ParseKey(probe *KeyProbe, unmarshaler KeyUnmarshaler, payload []byte) (Key, error) {
	return f(probe, unmarshaler, payload)
}

var muKeyParser sync.RWMutex
var keyParsers = []KeyParser{KeyParseFunc(defaultParseKey)}

// RegisterKeyParser adds a new KeyParser. Parsers are called in FILO order.
// That is, the last parser to be registered is called first. There is no
// check for duplicate entries.
func RegisterKeyParser(kp KeyParser) {
	muKeyParser.Lock()
	defer muKeyParser.Unlock()
	keyParsers = append(keyParsers, kp)
}

// FromRaw creates a jwk.Key from the given key (RSA/ECDSA/symmetric keys).
//
// The constructor auto-detects the type of key to be instantiated
// based on the input type:
//
//   - "crypto/rsa".PrivateKey and "crypto/rsa".PublicKey creates an RSA based key
//   - "crypto/ecdsa".PrivateKey and "crypto/ecdsa".PublicKey creates an EC based key
//   - "crypto/ed25519".PrivateKey and "crypto/ed25519".PublicKey creates an OKP based key
//   - []byte creates a symmetric key
func FromRaw(key interface{}) (Key, error) {
	if key == nil {
		return nil, fmt.Errorf(`jwk.FromRaw requires a non-nil key`)
	}

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
		return nil, fmt.Errorf(`invalid key type '%T' for jwk.New`, key)
	}
}

// PublicSetOf returns a new jwk.Set consisting of
// public keys of the keys contained in the set.
//
// This is useful when you are generating a set of private keys, and
// you want to generate the corresponding public versions for the
// users to verify with.
//
// Be aware that all fields will be copied onto the new public key. It is the caller's
// responsibility to remove any fields, if necessary.
func PublicSetOf(v Set) (Set, error) {
	newSet := NewSet()

	n := v.Len()
	for i := 0; i < n; i++ {
		k, ok := v.Key(i)
		if !ok {
			return nil, fmt.Errorf(`key not found`)
		}
		pubKey, err := PublicKeyOf(k)
		if err != nil {
			return nil, fmt.Errorf(`failed to get public key of %T: %w`, k, err)
		}
		if err := newSet.AddKey(pubKey); err != nil {
			return nil, fmt.Errorf(`failed to add key to public key set: %w`, err)
		}
	}

	return newSet, nil
}

// PublicKeyOf returns the corresponding public version of the jwk.Key.
// If `v` is a SymmetricKey, then the same value is returned.
// If `v` is already a public key, the key itself is returned.
//
// If `v` is a private key type that has a `PublicKey()` method, be aware
// that all fields will be copied onto the new public key. It is the caller's
// responsibility to remove any fields, if necessary
//
// If `v` is a raw key, the key is first converted to a `jwk.Key`
func PublicKeyOf(v interface{}) (Key, error) {
	// This should catch all jwk.Key instances
	if pk, ok := v.(PublicKeyer); ok {
		return pk.PublicKey()
	}

	jk, err := FromRaw(v)
	if err != nil {
		return nil, fmt.Errorf(`failed to convert key into JWK: %w`, err)
	}

	return jk.PublicKey()
}

// PublicRawKeyOf returns the corresponding public key of the given
// value `v` (e.g. given *rsa.PrivateKey, *rsa.PublicKey is returned)
// If `v` is already a public key, the key itself is returned.
//
// The returned value will always be a pointer to the public key,
// except when a []byte (e.g. symmetric key, ed25519 key) is passed to `v`.
// In this case, the same []byte value is returned.
func PublicRawKeyOf(v interface{}) (interface{}, error) {
	if pk, ok := v.(PublicKeyer); ok {
		pubk, err := pk.PublicKey()
		if err != nil {
			return nil, fmt.Errorf(`failed to obtain public key from %T: %w`, v, err)
		}

		var raw interface{}
		if err := pubk.Raw(&raw); err != nil {
			return nil, fmt.Errorf(`failed to obtain raw key from %T: %w`, pubk, err)
		}
		return raw, nil
	}

	// This may be a silly idea, but if the user gave us a non-pointer value...
	var ptr interface{}
	switch v := v.(type) {
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

	switch x := ptr.(type) {
	case *rsa.PrivateKey:
		return &x.PublicKey, nil
	case *rsa.PublicKey:
		return x, nil
	case *ecdsa.PrivateKey:
		return &x.PublicKey, nil
	case *ecdsa.PublicKey:
		return x, nil
	case ed25519.PrivateKey:
		return x.Public(), nil
	case ed25519.PublicKey:
		return x, nil
	case x25519.PrivateKey:
		return x.Public(), nil
	case x25519.PublicKey:
		return x, nil
	case []byte:
		return x, nil
	default:
		return nil, fmt.Errorf(`invalid key type passed to PublicKeyOf (%T)`, v)
	}
}

const (
	pmPrivateKey    = `PRIVATE KEY`
	pmPublicKey     = `PUBLIC KEY`
	pmECPrivateKey  = `EC PRIVATE KEY`
	pmRSAPublicKey  = `RSA PUBLIC KEY`
	pmRSAPrivateKey = `RSA PRIVATE KEY`
)

// EncodeX509 encodes the key into a byte sequence in ASN.1 DER format
// suitable for to be PEM encoded. The key can be a jwk.Key or a raw key
// instance, but it must be one of the types supported by `x509` package.
//
// This function will try to do the right thing depending on the key type
// (i.e. switch between `x509.MarshalPKCS1PRivateKey` and `x509.MarshalECPrivateKey`),
// but for public keys, it will always use `x509.MarshalPKIXPublicKey`.
// Please manually perform the encoding if you need more fine grained control
//
// The first return value is the name that can be used for `(pem.Block).Type`.
// The second return value is the encoded byte sequence.
func EncodeX509(v interface{}) (string, []byte, error) {
	// we can't import jwk, so just use the interface
	if key, ok := v.(interface{ Raw(interface{}) error }); ok {
		var raw interface{}
		if err := key.Raw(&raw); err != nil {
			return "", nil, fmt.Errorf(`failed to get raw key out of %T: %w`, key, err)
		}

		v = raw
	}

	// Try to convert it into a certificate
	switch v := v.(type) {
	case *rsa.PrivateKey:
		return pmRSAPrivateKey, x509.MarshalPKCS1PrivateKey(v), nil
	case *ecdsa.PrivateKey:
		marshaled, err := x509.MarshalECPrivateKey(v)
		if err != nil {
			return "", nil, err
		}
		return pmECPrivateKey, marshaled, nil
	case ed25519.PrivateKey:
		marshaled, err := x509.MarshalPKCS8PrivateKey(v)
		if err != nil {
			return "", nil, err
		}
		return pmPrivateKey, marshaled, nil
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		marshaled, err := x509.MarshalPKIXPublicKey(v)
		if err != nil {
			return "", nil, err
		}
		return pmPublicKey, marshaled, nil
	default:
		return "", nil, fmt.Errorf(`unsupported type %T for ASN.1 DER encoding`, v)
	}
}

// EncodePEM encodes the key into a PEM encoded ASN.1 DER format.
// The key can be a jwk.Key or a raw key instance, but it must be one of
// the types supported by `x509` package.
//
// Internally, it uses the same routine as `jwk.EncodeX509()`, and therefore
// the same caveats apply
func EncodePEM(v interface{}) ([]byte, error) {
	typ, marshaled, err := EncodeX509(v)
	if err != nil {
		return nil, fmt.Errorf(`failed to encode key in x509: %w`, err)
	}

	block := &pem.Block{
		Type:  typ,
		Bytes: marshaled,
	}
	return pem.EncodeToMemory(block), nil
}

// DecodePEM decodes a key in PEM encoded ASN.1 DER format.
// and returns a raw key
func DecodePEM(src []byte) (interface{}, []byte, error) {
	block, rest := pem.Decode(src)
	if block == nil {
		return nil, nil, fmt.Errorf(`failed to decode PEM data`)
	}

	switch block.Type {
	// Handle the semi-obvious cases
	case pmRSAPrivateKey:
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf(`failed to parse PKCS1 private key: %w`, err)
		}
		return key, rest, nil
	case pmRSAPublicKey:
		key, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf(`failed to parse PKCS1 public key: %w`, err)
		}
		return key, rest, nil
	case pmECPrivateKey:
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf(`failed to parse EC private key: %w`, err)
		}
		return key, rest, nil
	case pmPublicKey:
		// XXX *could* return dsa.PublicKey
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf(`failed to parse PKIX public key: %w`, err)
		}
		return key, rest, nil
	case pmPrivateKey:
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf(`failed to parse PKCS8 private key: %w`, err)
		}
		return key, rest, nil
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf(`failed to parse certificate: %w`, err)
		}
		return cert.PublicKey, rest, nil
	default:
		return nil, nil, fmt.Errorf(`invalid PEM block type %s`, block.Type)
	}
}

// ParseRawKey is a combination of ParseKey and Raw. It parses a single JWK key,
// and assigns the "raw" key to the given parameter. The key must either be
// a pointer to an empty interface, or a pointer to the actual raw key type
// such as *rsa.PrivateKey, *ecdsa.PublicKey, *[]byte, etc.
func ParseRawKey(data []byte, rawkey interface{}) error {
	key, err := ParseKey(data)
	if err != nil {
		return fmt.Errorf(`failed to parse key: %w`, err)
	}

	if err := key.Raw(rawkey); err != nil {
		return fmt.Errorf(`failed to assign to raw key variable: %w`, err)
	}

	return nil
}

type setDecodeCtx struct {
	json.DecodeCtx
	ignoreParseError bool
}

func (ctx *setDecodeCtx) IgnoreParseError() bool {
	return ctx.ignoreParseError
}

// ParseKey parses a single key JWK. Unlike `jwk.Parse` this method will
// report failure if you attempt to pass a JWK set. Only use this function
// when you know that the data is a single JWK.
//
// Given a WithPEM(true) option, this function assumes that the given input
// is PEM encoded ASN.1 DER format key.
//
// Note that a successful parsing of any type of key does NOT necessarily
// guarantee a valid key. For example, no checks against expiration dates
// are performed for certificate expiration, no checks against missing
// parameters are performed, etc.
func ParseKey(data []byte, options ...ParseOption) (Key, error) {
	var parsePEM bool
	var localReg *json.Registry
	for _, option := range options {
		//nolint:forcetypeassert
		switch option.Ident() {
		case identPEM{}:
			parsePEM = option.Value().(bool)
		case identLocalRegistry{}:
			// in reality you can only pass either withLocalRegistry or
			// WithTypedField, but since withLocalRegistry is used only by us,
			// we skip checking
			localReg = option.Value().(*json.Registry)
		case identTypedField{}:
			pair := option.Value().(typedFieldPair)
			if localReg == nil {
				localReg = json.NewRegistry()
			}
			localReg.Register(pair.Name, pair.Value)
		case identIgnoreParseError{}:
			return nil, fmt.Errorf(`jwk.WithIgnoreParseError() cannot be used for ParseKey()`)
		}
	}

	if parsePEM {
		raw, _, err := DecodePEM(data)
		if err != nil {
			return nil, fmt.Errorf(`failed to parse PEM encoded key: %w`, err)
		}
		return FromRaw(raw)
	}

	probe, err := keyProbe.Probe(data)
	if err != nil {
		return nil, fmt.Errorf(`jwk.Parse: failed to probe data: %w`, err)
	}

	unmarshaler := keyUnmarshaler{localReg: localReg}

	muKeyParser.RLock()
	parsers := make([]KeyParser, len(keyParsers))
	copy(parsers, keyParsers)
	muKeyParser.RUnlock()

	for i := len(parsers) - 1; i >= 0; i-- {
		parser := parsers[i]
		key, err := parser.ParseKey(probe, &unmarshaler, data)
		if err == nil {
			return key, nil
		}

		if IsContiueParseError(err) {
			continue
		}

		return nil, err
	}
	return nil, fmt.Errorf(`jwk.Parse: no parser was able to parse the key`)
}

func defaultParseKey(probe *KeyProbe, unmarshaler KeyUnmarshaler, data []byte) (Key, error) {
	var key Key
	var kty string
	var d json.RawMessage
	if err := probe.Get("Kty", &kty); err != nil {
		return nil, fmt.Errorf(`jwk.Parse: failed to get "kty" hint: %w`, err)
	}
	// We ignore errors from this field, as it's optional
	_ = probe.Get("D", &d)
	switch jwa.KeyType(kty) {
	case jwa.RSA:
		if d != nil {
			key = newRSAPrivateKey()
		} else {
			key = newRSAPublicKey()
		}
	case jwa.EC:
		if d != nil {
			key = newECDSAPrivateKey()
		} else {
			key = newECDSAPublicKey()
		}
	case jwa.OctetSeq:
		key = newSymmetricKey()
	case jwa.OKP:
		if d != nil {
			key = newOKPPrivateKey()
		} else {
			key = newOKPPublicKey()
		}
	default:
		return nil, fmt.Errorf(`invalid key type from JSON (%s)`, kty)
	}

	if err := unmarshaler.UnmarshalKey(data, key); err != nil {
		return nil, fmt.Errorf(`failed to unmarshal JSON into key (%T): %w`, key, err)
	}
	return key, nil
}

type keyUnmarshaler struct {
	localReg *json.Registry
}

func (ku *keyUnmarshaler) UnmarshalKey(data []byte, key interface{}) error {
	if ku.localReg != nil {
		dcKey, ok := key.(json.DecodeCtxContainer)
		if !ok {
			return fmt.Errorf(`typed field was requested, but the key (%T) does not support DecodeCtx`, key)
		}
		dc := json.NewDecodeCtx(ku.localReg)
		dcKey.SetDecodeCtx(dc)
		defer func() { dcKey.SetDecodeCtx(nil) }()
	}

	if err := json.Unmarshal(data, key); err != nil {
		return fmt.Errorf(`failed to unmarshal JSON into key (%T): %w`, key, err)
	}

	return nil
}

// Parse parses JWK from the incoming []byte.
//
// For JWK sets, this is a convenience function. You could just as well
// call `json.Unmarshal` against an empty set created by `jwk.NewSet()`
// to parse a JSON buffer into a `jwk.Set`.
//
// This function exists because many times the user does not know before hand
// if a JWK(s) resource at a remote location contains a single JWK key or
// a JWK set, and `jwk.Parse()` can handle either case, returning a JWK Set
// even if the data only contains a single JWK key
//
// If you are looking for more information on how JWKs are parsed, or if
// you know for sure that you have a single key, please see the documentation
// for `jwk.ParseKey()`.
func Parse(src []byte, options ...ParseOption) (Set, error) {
	var parsePEM bool
	var localReg *json.Registry
	var ignoreParseError bool
	for _, option := range options {
		//nolint:forcetypeassert
		switch option.Ident() {
		case identPEM{}:
			parsePEM = option.Value().(bool)
		case identIgnoreParseError{}:
			ignoreParseError = option.Value().(bool)
		case identTypedField{}:
			pair := option.Value().(typedFieldPair)
			if localReg == nil {
				localReg = json.NewRegistry()
			}
			localReg.Register(pair.Name, pair.Value)
		}
	}

	s := NewSet()

	if parsePEM {
		src = bytes.TrimSpace(src)
		for len(src) > 0 {
			raw, rest, err := DecodePEM(src)
			if err != nil {
				return nil, fmt.Errorf(`failed to parse PEM encoded key: %w`, err)
			}
			key, err := FromRaw(raw)
			if err != nil {
				return nil, fmt.Errorf(`failed to create jwk.Key from %T: %w`, raw, err)
			}
			if err := s.AddKey(key); err != nil {
				return nil, fmt.Errorf(`failed to add jwk.Key to set: %w`, err)
			}
			src = bytes.TrimSpace(rest)
		}
		return s, nil
	}

	if localReg != nil || ignoreParseError {
		dcKs, ok := s.(KeyWithDecodeCtx)
		if !ok {
			return nil, fmt.Errorf(`typed field was requested, but the key set (%T) does not support DecodeCtx`, s)
		}
		dc := &setDecodeCtx{
			DecodeCtx:        json.NewDecodeCtx(localReg),
			ignoreParseError: ignoreParseError,
		}
		dcKs.SetDecodeCtx(dc)
		defer func() { dcKs.SetDecodeCtx(nil) }()
	}

	if err := json.Unmarshal(src, s); err != nil {
		return nil, fmt.Errorf(`failed to unmarshal JWK set: %w`, err)
	}

	return s, nil
}

// ParseReader parses a JWK set from the incoming byte buffer.
func ParseReader(src io.Reader, options ...ParseOption) (Set, error) {
	// meh, there's no way to tell if a stream has "ended" a single
	// JWKs except when we encounter an EOF, so just... ReadAll
	buf, err := io.ReadAll(src)
	if err != nil {
		return nil, fmt.Errorf(`failed to read from io.Reader: %w`, err)
	}

	return Parse(buf, options...)
}

// ParseString parses a JWK set from the incoming string.
func ParseString(s string, options ...ParseOption) (Set, error) {
	return Parse([]byte(s), options...)
}

// AssignKeyID is a convenience function to automatically assign the "kid"
// section of the key, if it already doesn't have one. It uses Key.Thumbprint
// method with crypto.SHA256 as the default hashing algorithm
func AssignKeyID(key Key, options ...AssignKeyIDOption) error {
	if key.Has(KeyIDKey) {
		return nil
	}

	hash := crypto.SHA256
	for _, option := range options {
		//nolint:forcetypeassert
		switch option.Ident() {
		case identThumbprintHash{}:
			hash = option.Value().(crypto.Hash)
		}
	}

	h, err := key.Thumbprint(hash)
	if err != nil {
		return fmt.Errorf(`failed to generate thumbprint: %w`, err)
	}

	if err := key.Set(KeyIDKey, base64.EncodeToString(h)); err != nil {
		return fmt.Errorf(`failed to set "kid": %w`, err)
	}

	return nil
}

func cloneKey(src Key) (Key, error) {
	var dst Key
	switch src.(type) {
	case RSAPrivateKey:
		dst = newRSAPrivateKey()
	case RSAPublicKey:
		dst = newRSAPublicKey()
	case ECDSAPrivateKey:
		dst = newECDSAPrivateKey()
	case ECDSAPublicKey:
		dst = newECDSAPublicKey()
	case OKPPrivateKey:
		dst = newOKPPrivateKey()
	case OKPPublicKey:
		dst = newOKPPublicKey()
	case SymmetricKey:
		dst = newSymmetricKey()
	default:
		return nil, fmt.Errorf(`unknown key type %T`, src)
	}

	for _, pair := range src.makePairs() {
		//nolint:forcetypeassert
		key := pair.Key.(string)
		if err := dst.Set(key, pair.Value); err != nil {
			return nil, fmt.Errorf(`failed to set %q: %w`, key, err)
		}
	}
	return dst, nil
}

// Pem serializes the given jwk.Key in PEM encoded ASN.1 DER format,
// using either PKCS8 for private keys and PKIX for public keys.
// If you need to encode using PKCS1 or SEC1, you must do it yourself.
//
// # Argument must be of type jwk.Key or jwk.Set
//
// Currently only EC (including Ed25519) and RSA keys (and jwk.Set
// comprised of these key types) are supported.
func Pem(v interface{}) ([]byte, error) {
	var set Set
	switch v := v.(type) {
	case Key:
		set = NewSet()
		if err := set.AddKey(v); err != nil {
			return nil, fmt.Errorf(`failed to add key to set: %w`, err)
		}
	case Set:
		set = v
	default:
		return nil, fmt.Errorf(`argument to Pem must be either jwk.Key or jwk.Set: %T`, v)
	}

	var ret []byte
	for i := 0; i < set.Len(); i++ {
		key, _ := set.Key(i)
		typ, buf, err := asnEncode(key)
		if err != nil {
			return nil, fmt.Errorf(`failed to encode content for key #%d: %w`, i, err)
		}

		var block pem.Block
		block.Type = typ
		block.Bytes = buf
		ret = append(ret, pem.EncodeToMemory(&block)...)
	}
	return ret, nil
}

func asnEncode(key Key) (string, []byte, error) {
	switch key := key.(type) {
	case RSAPrivateKey, ECDSAPrivateKey, OKPPrivateKey:
		var rawkey interface{}
		if err := key.Raw(&rawkey); err != nil {
			return "", nil, fmt.Errorf(`failed to get raw key from jwk.Key: %w`, err)
		}
		buf, err := x509.MarshalPKCS8PrivateKey(rawkey)
		if err != nil {
			return "", nil, fmt.Errorf(`failed to marshal PKCS8: %w`, err)
		}
		return pmPrivateKey, buf, nil
	case RSAPublicKey, ECDSAPublicKey, OKPPublicKey:
		var rawkey interface{}
		if err := key.Raw(&rawkey); err != nil {
			return "", nil, fmt.Errorf(`failed to get raw key from jwk.Key: %w`, err)
		}
		buf, err := x509.MarshalPKIXPublicKey(rawkey)
		if err != nil {
			return "", nil, fmt.Errorf(`failed to marshal PKIX: %w`, err)
		}
		return pmPublicKey, buf, nil
	default:
		return "", nil, fmt.Errorf(`unsupported key type %T`, key)
	}
}

// RegisterCustomField allows users to specify that a private field
// be decoded as an instance of the specified type. This option has
// a global effect.
//
// For example, suppose you have a custom field `x-birthday`, which
// you want to represent as a string formatted in RFC3339 in JSON,
// but want it back as `time.Time`.
//
// In such case you would register a custom field as follows
//
//	jwk.RegisterCustomField(`x-birthday`, time.Time{})
//
// Then you can use a `time.Time` variable to extract the value
// of `x-birthday` field, instead of having to use `interface{}`
// and later convert it to `time.Time`
//
//	var bday time.Time
//	_ = key.Get(`x-birthday`, &bday)
func RegisterCustomField(name string, object interface{}) {
	registry.Register(name, object)
}

// Equal compares two keys and returns true if they are equal. The comparison
// is solely done against the thumbprints of k1 and k2. It is possible for keys
// that have, for example, different key IDs, key usage, etc, to be considered equal.
func Equal(k1, k2 Key) bool {
	h := crypto.SHA256
	tp1, err := k1.Thumbprint(h)
	if err != nil {
		return false // can't report error
	}
	tp2, err := k2.Thumbprint(h)
	if err != nil {
		return false // can't report error
	}

	return bytes.Equal(tp1, tp2)
}

// IsPrivateKey returns true if the supplied key is a private key of an
// asymmetric key pair. The argument `k` must implement the `AsymmetricKey`
// interface.
//
// An error is returned if the supplied key is not an `AsymmetricKey`.
func IsPrivateKey(k Key) (bool, error) {
	asymmetric, ok := k.(AsymmetricKey)
	if ok {
		return asymmetric.IsPrivate(), nil
	}
	return false, fmt.Errorf("jwk.IsPrivateKey: %T is not an asymmetric key", k)
}
