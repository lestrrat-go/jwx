package jwk

import (
	"fmt"
	"reflect"
	"sync"

	"github.com/lestrrat-go/blackmagic"
	"github.com/lestrrat-go/jwx/v3/internal/json"
	"github.com/lestrrat-go/jwx/v3/jwa"
)

// KeyParser represents a type that can parse a JSON representation of a JWK into
// a jwk.Key.
// See KeyConvertor for a type that can convert a raw key into a jwk.Key
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

// protects keyParsers
var muKeyParser sync.RWMutex

// list of parsers
var keyParsers = []KeyParser{KeyParseFunc(defaultParseKey)}

// RegisterKeyParser adds a new KeyParser. Parsers are called in FILO order.
// That is, the last parser to be registered is called first. There is no
// check for duplicate entries.
//
// You can use a JWK that this library does not implement out of the box by
// registering a new `KeyParser` that can produce your custom JWK. For example,
// you may register a new parser and a key probe field like this:
//
//	func init() {
//	  // optional
//	  jwk.RegiserProbeField(reflect.StructField{Name: "SomeHint", Type: reflect.TypeOf(""), Tag: `json:"some_hint"`})
//	  jwk.RegisterKeyParser(&MyKeyParser{})
//	}
//
// In order to understand how this works, you need to understand
// how the `jwk.ParseKey()` works.
//
// The first thing that occurs when parsing a key is a partial
// unmarshaling of the payload into a hint / probe object.
// This must be done because when going from JSON to a concrete Go type,
// we must first create a concrete Go type _and then_ use `json.Unmarshal`
// to parse the JSON payload.
//
//	key := NewMyKey()
//	_ = json.Unmarshal(payload, key)
//
// But in order to create the concrete type, we need to know what kind of
// Go type we need. This can only be done by peeking into the payload.
// To do this, we use a struct that populates the minimal amount of
// information required to determine the concrete type.
//
//	var probe ...
//	_ = json.Unmarshal(payload, &probe)
//	if probe.Hint == ... { /* pseudocode */
//	  concrete := newAwesomeToken() /* we now know the concrete type! */
//	  if err := json.Unmarshal(payload, concrete) { ... }
//	}
//
// For the built-in types, we only need to know the value of the "kty"
// and "d" fields, to determine the key type (via "kty") and if it's
// a private or public key (via "d").
//
// For example, a JWK representing an RSA key would look like:
//
//	{ "kty": "RSA", "n": ..., "e": ..., ... }
//
// The KeyProbe partially unmarshals this object so that we can obtain the value
// of the field "kty". By inspecting the value of this field, we can determine
// that this is an RSA key. Following code shows the rough idea of how the
// key type is determined:
//
//	var kty string
//	_ = probe.Get("Kty", &kty)
//	switch kty {
//	case "RSA":
//	  // create an RSA key
//	case "EC":
//	  // create an EC key
//	...
//	}
//
// However this is not enough. We also need to know if this is a private
// or public key. In the case of an RSA key, the key is a private key if said payload contains
// some value in the "d" field.
//
//	 var key jwk.Key
//	 switch kty {
//	 case "RSA":
//	   var d json.RawMessage
//	   _ = probe.Get("D", &d)
//	   if len(d) > 0 {
//		    key = newRSAPrivateKey()
//	   } else {
//	     key = newRSAPublicKey()
//	   }
//	   ...
//	 }
//
// In this way we can finally unmarshal the payload into a concrete type.
//
// For most cases, the default KeyProbe implementation should be sufficient.
// However, in some cases you may need to query additional fields to determine
// to determine the concrete type.
// For example, if you want to know the value of the field "my_hint" (which holds a string value)
// from the payload, you can register it to be probed by registering an additional probe field like this:
//
//	jwk.RegisterProbeField(reflect.StructField{Name: "MyHint", Type: reflect.TypeOf(""), Tag: `json:"my_hint"`})
//
// This will add a new field to the KeyProbe object dynamically, allowing it to
// capture the value of the "my_hint" field from the payload and store it in
// the "MyHint" slot of the probe.
//
// This probe will be passed to the registered parsers' `ParseKey()` methods.
// This is why the `KeyParser` interface contains the `*jwk.KeyProbe` object
// as its first argument. Following is how you would query the value of
// "MyHint" from the probe:
//
//	func(*MyKeyParser) ParseKey(rawProbe *KeyProbe, unmarshaler KeyUnmarshaler, data []byte) (jwk.Key, error) {
//	  var hint string
//	  if err := probe.Get("MyHint", &hint); err != nil { ... }
//	  ...
//	}
//
// The second argument is a `KeyUnmarshaler` object. This is a thin wrapper
// `json.Unmarshal`. It works almost identical to `json.Unmarshal`, but
// adds extra magic that is specific to this library before calling
// the actual `json.Unmarshal`, but unfortunately you would need to know the
// internals of this library to fully use its magic. If you do not care
// about the details, just use the unmarshaler as you would `json.Unmarshal`.
//
// Combining this together, the following is how you would add a new `jwk.Key`
//
//	func init() {
//	  jwk.RegisterFieldProbe(reflect.StructField{Name: "MyHint", Type: reflect.TypeOf(""), Tag: `json:"my_hint"`})
//	  jwk.RegisterParser(&MyKeyParser{})
//	}
//
//	type MyKeyParser struct { ... }
//	func(*MyKeyParser) ParseKey(rawProbe *KeyProbe, unmarshaler KeyUnmarshaler, data []byte) (jwk.Key, error) {
//	  // Create concrete type
//	  var hint string
//	  if err := probe.Get("MyHint", &hint); err != nil {
//	     // if it doesn't have the `my_hint` field, it probably means
//	     // it's not for us, so we return ContinueParseError so that
//	     // the next parser can pick it up
//	     return nil, jwk.ContinueParseError()
//	  }
//
//	  // Use hint to determine concrete key type
//	  var key jwk.Key
//	  switch hint {
//	  case ...:
//	   key = = myNewAwesomeJWK()
//	  ...
//
//	  return unmarshaler.Unmarshal(data, key)
//	}
//
// This functionality should be considered experimental. While we
// expect that the functionality itself will remain, the API may
// change in backward incompatible ways, even during minor version
// releases.
func RegisterKeyParser(kp KeyParser) {
	muKeyParser.Lock()
	defer muKeyParser.Unlock()
	keyParsers = append(keyParsers, kp)
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
