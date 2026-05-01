package jwk

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"maps"
	"sync"

	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/lestrrat-go/jwx/v4/internal/pool"
	"github.com/lestrrat-go/jwx/v4/jwa"
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
	// return a `jwk.ContinueError()`. Any other errors will immediately
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
// The error return is reserved for future validation. The current
// implementation always returns nil, but callers — especially extension
// modules calling this from init() — must check the return value and panic
// on failure to stay forward-compatible.
func RegisterKeyParser(kp KeyParser) error {
	muKeyParser.Lock()
	defer muKeyParser.Unlock()
	keyParsers = append(keyParsers, kp)
	return nil
}

func defaultParseKey(probe *KeyProbe, unmarshaler KeyUnmarshaler, data []byte) (Key, error) {
	var key Key
	ktyV, ok := probe.Field("Kty")
	if !ok {
		return nil, fmt.Errorf(`jwk.Parse: %w`, UnknownKeyTypeError{})
	}
	kty, ok := ktyV.(string)
	if !ok {
		return nil, fmt.Errorf(`jwk.Parse: "kty" hint is not a string`)
	}
	// We ignore errors from this field, as it's optional
	dV, _ := probe.Field("D")
	d, _ := dV.(json.RawMessage)
	switch v, _ := jwa.LookupKeyType(kty); v {
	case jwa.RSA():
		if d != nil {
			key = newRSAPrivateKey()
		} else {
			key = newRSAPublicKey()
		}
	case jwa.EC():
		if d != nil {
			key = newECDSAPrivateKey()
		} else {
			key = newECDSAPublicKey()
		}
	case jwa.OctetSeq():
		key = newSymmetricKey()
	case jwa.OKP():
		if d != nil {
			key = newOKPPrivateKey()
		} else {
			key = newOKPPublicKey()
		}
	case jwa.AKP():
		// AKP keys use "priv" instead of "d" for private key material
		privV, _ := probe.Field("Priv")
		priv, _ := privV.(json.RawMessage)
		if priv != nil {
			key = newAKPPrivateKey()
		} else {
			key = newAKPPublicKey()
		}
	default:
		return nil, UnknownKeyTypeError{KeyType: kty}
	}

	if err := unmarshaler.UnmarshalKey(data, key); err != nil {
		return nil, fmt.Errorf(`failed to unmarshal JSON into key (%T): %w`, key, err)
	}
	return key, nil
}

type keyUnmarshaler struct {
	localReg *json.Registry
}

func (ku *keyUnmarshaler) UnmarshalKey(data []byte, key any) error {
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

// probeFieldDef describes how to extract a single field from raw JSON.
type probeFieldDef struct {
	jsonKey  string
	index    int
	readFrom func(*jsontext.Decoder) (any, error)
}

// keyProber is the object that starts the probing. When Probe() is called,
// it streams through the JSON payload and only extracts the registered
// fields, skipping everything else.
type keyProber struct {
	mu       sync.RWMutex
	fields   []probeFieldDef
	names    map[string]int            // Go name -> index
	jsonKeys map[string]*probeFieldDef // json key -> def
	pool     *pool.Pool[[]any]
}

func (kp *keyProber) addField(name string, def probeFieldDef) error {
	kp.mu.Lock()
	defer kp.mu.Unlock()

	if _, ok := kp.names[name]; ok {
		return fmt.Errorf(`field name %s is already registered`, name)
	}

	def.index = len(kp.fields)
	kp.fields = append(kp.fields, def)

	// Replace kp.names with a fresh map. KeyProbe instances created by
	// earlier Probe calls keep their reference to the old map, which is
	// never mutated again — so KeyProbe.Field reads stay safe even while
	// a concurrent RegisterProbeField runs.
	names := make(map[string]int, len(kp.fields))
	maps.Copy(names, kp.names)
	names[name] = def.index
	kp.names = names

	// Rebuild jsonKeys lookup
	kp.jsonKeys = make(map[string]*probeFieldDef, len(kp.fields))
	for i := range kp.fields {
		kp.jsonKeys[kp.fields[i].jsonKey] = &kp.fields[i]
	}

	// Rebuild pool for new slice size
	n := len(kp.fields)
	kp.pool = pool.New(
		func() []any { return make([]any, n) },
		func(s []any) []any { clear(s); return s },
	)
	return nil
}

// probeTarget implements json.UnmarshalerFrom to use the pooled decoder
// from json.Unmarshal, avoiding the overhead of creating a standalone decoder.
type probeTarget struct {
	kp      *keyProber
	results []any
}

func (pt *probeTarget) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	// Consume opening '{'
	tok, err := dec.ReadToken()
	if err != nil {
		return err
	}
	if tok.Kind() != '{' {
		return fmt.Errorf(`probe: expected object, got %s`, tok.Kind())
	}

	remaining := len(pt.kp.fields)
	for dec.PeekKind() != '}' {
		// Read key
		tok, err = dec.ReadToken()
		if err != nil {
			return err
		}
		key := tok.String()

		def, ok := pt.kp.jsonKeys[key]
		// Skip when: the key is not registered for probing, we've
		// already filled every slot, OR this slot is already filled
		// (a duplicate occurrence of an earlier field — first-wins).
		// Without the duplicate-skip, N repeats of one field would
		// drain `remaining` and prevent later registered fields from
		// being read, silently misclassifying the key.
		if !ok || remaining <= 0 || pt.results[def.index] != nil {
			if err := dec.SkipValue(); err != nil {
				return err
			}
			continue
		}

		v, err := def.readFrom(dec)
		if err != nil {
			return err
		}
		pt.results[def.index] = v
		remaining--
	}

	// Consume closing '}'
	if _, err := dec.ReadToken(); err != nil {
		return err
	}

	return nil
}

func (kp *keyProber) Probe(data []byte) (*KeyProbe, error) {
	kp.mu.RLock()
	defer kp.mu.RUnlock()

	results := kp.pool.Get()

	pt := probeTarget{kp: kp, results: results}
	if err := jsonv2.Unmarshal(data, &pt, jsontext.AllowDuplicateNames(true)); err != nil {
		return nil, fmt.Errorf(`probe: %w`, err)
	}

	return &KeyProbe{results: results, names: kp.names}, nil
}

// KeyProbe is the object that carries the hints when parsing a key.
// The exact list of fields can vary depending on the types of key
// that are registered.
//
// Use `Field()` to access the value of a field.
type KeyProbe struct {
	results []any
	names   map[string]int // shared reference, not copied
}

// Field returns the value of the field with the given `name`,
// along with a boolean indicating whether the field was found.
// The field type is determined by the type registered through
// `jwk.RegisterProbeField()`.
func (kp *KeyProbe) Field(name string) (any, bool) {
	idx, ok := kp.names[name]
	if !ok {
		return nil, false
	}
	v := kp.results[idx]
	return v, v != nil
}

var keyProbe = &keyProber{
	names: make(map[string]int),
}

// readString reads a JSON string token directly from the decoder.
func readString(dec *jsontext.Decoder) (any, error) {
	tok, err := dec.ReadToken()
	if err != nil {
		return nil, err
	}
	return tok.String(), nil
}

// readRawValue reads a raw JSON value from the decoder, copying the bytes
// so the result outlives the decoder's buffer.
func readRawValue(dec *jsontext.Decoder) (any, error) {
	val, err := dec.ReadValue()
	if err != nil {
		return nil, err
	}
	return json.RawMessage(append([]byte{}, val...)), nil
}

// readGeneric reads a value by reading the raw JSON and unmarshaling it.
func readGeneric[T any](dec *jsontext.Decoder) (any, error) {
	val, err := dec.ReadValue()
	if err != nil {
		return nil, err
	}
	var v T
	if err := json.Unmarshal(val, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// RegisterProbeField adds a new field to be probed during the initial
// phase of parsing. This is done by streaming through the JSON payload
// and extracting only the registered fields, skipping everything else.
//
// The `name` parameter is used to identify the field when calling
// `KeyProbe.Field()`. The `jsonKey` parameter is the JSON field name
// to extract from the payload.
//
// The field name must be unique. If you believe that your field name may
// collide with other packages that may want to add their own probes,
// it is the responsibility of the caller to ensure that the field name
// is unique (possibly by prefixing the field name with a unique string).
// It is important to note that the field name need not be the same as the
// JSON field name. For example, your field name could be "MyPkg_MyHint",
// while the actual JSON field name could be "my_hint".
//
// If the field name is not unique, an error is returned.
func RegisterProbeField[T any](name, jsonKey string) error {
	var readFn func(*jsontext.Decoder) (any, error)
	switch any((*T)(nil)).(type) {
	case *string:
		readFn = readString
	case *json.RawMessage:
		readFn = readRawValue
	default:
		readFn = readGeneric[T]
	}

	return keyProbe.addField(name, probeFieldDef{
		jsonKey:  jsonKey,
		readFrom: readFn,
	})
}

// KeyUnmarshaler is a thin wrapper around json.Unmarshal. It behaves almost
// exactly like json.Unmarshal, but it allows us to add extra magic that
// is specific to this library before calling the actual json.Unmarshal.
type KeyUnmarshaler interface {
	UnmarshalKey(data []byte, key any) error
}
