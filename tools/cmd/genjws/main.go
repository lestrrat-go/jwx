package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/lestrrat-go/codegen"
)

func main() {
	if err := _main(); err != nil {
		log.Printf("%s", err)
		os.Exit(1)
	}
}

func _main() error {
	codegen.RegisterZeroVal(`jwa.SignatureAlgorithm`, `""`)

	var objectsFile = flag.String("objects", "objects.yml", "")
	flag.Parse()
	jsonSrc, err := yaml2json(*objectsFile)
	if err != nil {
		return err
	}

	var object codegen.Object
	if err := json.NewDecoder(bytes.NewReader(jsonSrc)).Decode(&object); err != nil {
		return fmt.Errorf(`failed to decode %q: %w`, *objectsFile, err)
	}

	object.Organize()
	return generateHeaders(&object)
}

func yaml2json(fn string) ([]byte, error) {
	in, err := os.Open(fn)
	if err != nil {
		return nil, fmt.Errorf(`failed to open %q: %w`, fn, err)
	}
	defer in.Close()

	var v interface{}
	if err := yaml.NewDecoder(in).Decode(&v); err != nil {
		return nil, fmt.Errorf(`failed to decode %q: %w`, fn, err)
	}

	return json.Marshal(v)
}

func IsPointer(f codegen.Field) bool {
	return strings.HasPrefix(f.Type(), `*`)
}

func PointerElem(f codegen.Field) string {
	return strings.TrimPrefix(f.Type(), `*`)
}

func fieldStorageType(s string) string {
	if fieldStorageTypeIsIndirect(s) {
		return `*` + s
	}
	return s
}

func fieldStorageTypeIsIndirect(s string) bool {
	return !(s == "jwk.Key" || strings.HasPrefix(s, `*`) || strings.HasPrefix(s, `[]`))
}

func generateHeaders(obj *codegen.Object) error {
	var buf bytes.Buffer

	o := codegen.NewOutput(&buf)
	o.L("// Code generated by tools/cmd/genjws/main.go. DO NOT EDIT.")
	o.LL("package jws")

	o.LL("const (")
	for _, f := range obj.Fields() {
		o.L("%sKey = %q", f.Name(true), f.JSON())
	}
	o.L(")") // end const

	o.LL("// Headers describe a standard Header set.")
	o.L("type Headers interface {")
	o.L("json.Marshaler")
	o.L("json.Unmarshaler")
	// These are the basic values that most jws have
	for _, f := range obj.Fields() {
		if f.Bool(`noDeref`) {
			o.L("%s() %s", f.GetterMethod(true), f.Type())
		} else {
			o.L("%s() %s", f.GetterMethod(true), PointerElem(f))
		}
	}

	// These are used to iterate through all keys in a header
	o.L("Iterate(ctx context.Context) Iterator")
	o.L("Walk(context.Context, Visitor) error")
	o.L("AsMap(context.Context) (map[string]interface{}, error)")
	o.L("Copy(context.Context, Headers) error")
	o.L("Merge(context.Context, Headers) (Headers, error)")

	// These are used to access a single element by key name
	o.L("Get(string, interface{}) error")
	o.L("Set(string, interface{}) error")
	o.L("Remove(string) error")
	o.L("Has(string) bool")

	o.LL("// PrivateParams returns the non-standard elements in the source structure")
	o.L("// WARNING: DO NOT USE PrivateParams() IF YOU HAVE CONCURRENT CODE ACCESSING THEM.")
	o.L("// Use AsMap() to get a copy of the entire header instead")
	o.L("PrivateParams() map[string]interface{}")
	o.L("}")

	o.LL("type stdHeaders struct {")
	for _, f := range obj.Fields() {
		if c := f.Comment(); c != "" {
			o.L("%s %s // %s", f.Name(false), fieldStorageType(f.Type()), c)
		} else {
			o.L("%s %s", f.Name(false), fieldStorageType(f.Type()))
		}
	}

	o.L("privateParams map[string]interface{}")
	o.L("mu *sync.RWMutex")
	o.L("dc DecodeCtx")
	o.L("raw []byte // stores the raw version of the header so it can be used later")
	o.L("}") // end type StandardHeaders

	o.LL("func NewHeaders() Headers {")
	o.L("return &stdHeaders{")
	o.L("mu: &sync.RWMutex{},")
	o.L("}")
	o.L("}")

	for _, f := range obj.Fields() {
		o.LL("func (h *stdHeaders) %s() %s{", f.GetterMethod(true), f.Type())
		o.L("h.mu.RLock()")
		o.L("defer h.mu.RUnlock()")
		if fieldStorageTypeIsIndirect(f.Type()) {
			o.L("if h.%s == nil {", f.Name(false))
			o.L("return %s", codegen.ZeroVal(f.Type()))
			o.L("}")
			o.L("return *(h.%s)", f.Name(false))
		} else {
			o.L("return h.%s", f.Name(false))
		}
		o.L("}") // func (h *stdHeaders) %s() %s
	}

	o.LL("func (h *stdHeaders) clear() {")
	for _, f := range obj.Fields() {
		o.L("h.%s = nil", f.Name(false))
	}
	o.L("h.privateParams = nil")
	o.L("h.raw = nil")
	o.L("}")

	o.LL("func (h *stdHeaders) DecodeCtx() DecodeCtx{")
	o.L("h.mu.RLock()")
	o.L("defer h.mu.RUnlock()")
	o.L("return h.dc")
	o.L("}")
	o.LL("func (h *stdHeaders) SetDecodeCtx(dc DecodeCtx) {")
	o.L("h.mu.Lock()")
	o.L("defer h.mu.Unlock()")
	o.L("h.dc = dc")
	o.L("}")

	// This has no lock because nothing can assign to it
	o.LL("func (h *stdHeaders) rawBuffer() []byte {")
	o.L("return h.raw")
	o.L("}")

	// Generate a function that iterates through all of the keys
	// in this header.
	o.LL("func (h *stdHeaders) makePairs() []*HeaderPair {")
	o.L("h.mu.RLock()")
	o.L("defer h.mu.RUnlock()")
	// NOTE: building up an array is *slow*?
	o.L("var pairs []*HeaderPair")
	for _, f := range obj.Fields() {
		o.L("if h.%s != nil {", f.Name(false))
		if fieldStorageTypeIsIndirect(f.Type()) {
			o.L("pairs = append(pairs, &HeaderPair{Key: %sKey, Value: *(h.%s)})", f.Name(true), f.Name(false))
		} else {
			o.L("pairs = append(pairs, &HeaderPair{Key: %sKey, Value: h.%s})", f.Name(true), f.Name(false))
		}
		o.L("}")
	}
	o.L("for k, v := range h.privateParams {")
	o.L("pairs = append(pairs, &HeaderPair{Key: k, Value: v})")
	o.L("}")
	o.L("sort.Slice(pairs, func(i, j int) bool {")
	o.L("return pairs[i].Key.(string) < pairs[j].Key.(string)")
	o.L("})")
	o.L("return pairs")
	o.L("}") // end of (h *stdHeaders) iterate(...)

	o.LL("func (h *stdHeaders) PrivateParams() map[string]interface{} {")
	o.L("h.mu.RLock()")
	o.L("defer h.mu.RUnlock()")
	o.L("return h.privateParams")
	o.L("}")

	o.LL("func (h *stdHeaders) Has(name string) bool {")
	o.L("h.mu.RLock()")
	o.L("defer h.mu.RUnlock()")
	o.L("switch name {")
	for _, f := range obj.Fields() {
		o.L("case %sKey:", f.Name(true))
		o.L("return h.%s != nil", f.Name(false))
	}
	o.L("default:")
	o.L("_, ok := h.privateParams[name]")
	o.L("return ok")
	o.L("}")
	o.L("}")

	o.LL("func (h *stdHeaders) Get(name string, dst interface{}) error {")
	o.L("h.mu.RLock()")
	o.L("defer h.mu.RUnlock()")
	o.L("switch name {")
	for _, f := range obj.Fields() {
		o.L("case %sKey:", f.Name(true))
		o.L("if h.%s == nil {", f.Name(false))
		o.L("return fmt.Errorf(`field %%q not found`, name)")
		o.L("}")
		o.L("if err := blackmagic.AssignIfCompatible(dst, ")
		if fieldStorageTypeIsIndirect(f.Type()) {
			o.R("*(h.%s)", f.Name(false))
		} else {
			o.L("h.%s", f.Name(false))
		}
		o.R("); err != nil {")
		o.L("return fmt.Errorf(`failed to assign value for field %%q: %%w`, name, err)")
		o.L("}")
		o.L("return nil")
	}
	o.L("default:")
	o.L("v, ok := h.privateParams[name]")
	o.L("if !ok {")
	o.L("return fmt.Errorf(`field %%q not found`, name)")
	o.L("}")
	o.L("if err := blackmagic.AssignIfCompatible(dst, v); err != nil {")
	o.L("return fmt.Errorf(`failed to assign value for field %%q: %%w`, name, err)")
	o.L("}")
	o.L("}") // end switch name
	o.L("return nil")
	o.L("}") // func (h *stdHeaders) Get(name string) (interface{}, bool)

	o.LL("func (h *stdHeaders) Set(name string, value interface{}) error {")
	o.L("h.mu.Lock()")
	o.L("defer h.mu.Unlock()")
	o.L("return h.setNoLock(name, value)")
	o.L("}")

	o.LL("func (h *stdHeaders) setNoLock(name string, value interface{}) error {")
	o.L("switch name {")
	for _, f := range obj.Fields() {
		o.L("case %sKey:", f.Name(true))
		if f.Bool(`hasAccept`) {
			o.L("var acceptor %s", PointerElem(f))
			o.L("if err := acceptor.Accept(value); err != nil {")
			o.L("return fmt.Errorf(`invalid value for %%s key: %%w`, %sKey, err)", f.Name(true))
			o.L("}") // end if err := h.%s.Accept(value)
			o.L("h.%s = &acceptor", f.Name(false))
			o.L("return nil")
		} else {
			o.L("if v, ok := value.(%s); ok {", f.Type())
			if fieldStorageTypeIsIndirect(f.Type()) {
				o.L("h.%s = &v", f.Name(false))
			} else {
				o.L("h.%s = v", f.Name(false))
			}
			o.L("return nil")
			o.L("}") // end if v, ok := value.(%s)
			o.L("return fmt.Errorf(`invalid value for %%s key: %%T`, %sKey, value)", f.Name(true))
		}
	}
	o.L("default:")
	o.L("if h.privateParams == nil {")
	o.L("h.privateParams = map[string]interface{}{}")
	o.L("}") // end if h.privateParams == nil
	o.L("h.privateParams[name] = value")
	o.L("}") // end switch name
	o.L("return nil")
	o.L("}")

	o.LL("func (h *stdHeaders) Remove(key string) error {")
	o.L("h.mu.Lock()")
	o.L("defer h.mu.Unlock()")
	o.L("switch key {")
	for _, f := range obj.Fields() {
		o.L("case %sKey:", f.Name(true))
		o.L("h.%s = nil", f.Name(false))
	}
	o.L("default:")
	o.L("delete(h.privateParams, key)")
	o.L("}")
	o.L("return nil") // currently unused, but who knows
	o.L("}")

	o.LL("func (h *stdHeaders) UnmarshalJSON(buf []byte) error {")
	o.L("h.mu.Lock()")
	o.L("defer h.mu.Unlock()")
	o.L("h.clear()")
	o.L("dec := json.NewDecoder(bytes.NewReader(buf))")
	o.L("LOOP:")
	o.L("for {")
	o.L("tok, err := dec.Token()")
	o.L("if err != nil {")
	o.L("return fmt.Errorf(`error reading token: %%w`, err)")
	o.L("}")
	o.L("switch tok := tok.(type) {")
	o.L("case json.Delim:")
	o.L("// Assuming we're doing everything correctly, we should ONLY")
	o.L("// get either '{' or '}' here.")
	o.L("if tok == '}' { // End of object")
	o.L("break LOOP")
	o.L("} else if tok != '{' {")
	o.L("return fmt.Errorf(`expected '{', but got '%%c'`, tok)")
	o.L("}")
	o.L("case string: // Objects can only have string keys")
	o.L("switch tok {")

	for _, f := range obj.Fields() {
		if f.Type() == "string" {
			o.L("case %sKey:", f.Name(true))
			o.L("if err := json.AssignNextStringToken(&h.%s, dec); err != nil {", f.Name(false))
			o.L("return fmt.Errorf(`failed to decode value for key %%s: %%w`, %sKey, err)", f.Name(true))
			o.L("}")
		} else if f.Type() == "[]byte" {
			o.L("case %sKey:", f.Name(true))
			o.L("if err := json.AssignNextBytesToken(&h.%s, dec); err != nil {", f.Name(false))
			o.L("return fmt.Errorf(`failed to decode value for key %%s`, %sKey, err)", f.Name(true))
			o.L("}")
		} else if f.Type() == "jwk.Key" {
			o.L("case %sKey:", f.Name(true))
			o.L("var buf json.RawMessage")
			o.L("if err := dec.Decode(&buf); err != nil {")
			o.L("return fmt.Errorf(`failed to decode value for key %%s: %%w`, %sKey, err)", f.Name(true))
			o.L("}")
			o.L("key, err := jwk.ParseKey(buf)")
			o.L("if err != nil {")
			o.L("return fmt.Errorf(`failed to parse JWK for key %%s: %%w`, %sKey, err)", f.Name(true))
			o.L("}")
			o.L("h.%s = key", f.Name(false))
		} else if strings.HasPrefix(f.Type(), "[]") {
			o.L("case %sKey:", f.Name(true))
			o.L("var decoded %s", f.Type())
			o.L("if err := dec.Decode(&decoded); err != nil {")
			o.L("return fmt.Errorf(`failed to decode value for key %%s: %%w`, %sKey, err)", f.Name(true))
			o.L("}")
			o.L("h.%s = decoded", f.Name(false))
		} else if f.Bool(`noDeref`) {
			o.L("case %sKey:", f.Name(true))
			o.L("var decoded %s", PointerElem(f))
			o.L("if err := dec.Decode(&decoded); err != nil {")
			o.L("return fmt.Errorf(`failed to decode value for key %%s: %%w`, %sKey, err)", f.Name(true))
			o.L("}")
			o.L("h.%s = &decoded", f.Name(false))
		} else {
			o.L("case %sKey:", f.Name(true))
			o.L("var decoded %s", f.Type())
			o.L("if err := dec.Decode(&decoded); err != nil {")
			o.L("return fmt.Errorf(`failed to decode value for key %%s: %%w`, %sKey, err)", f.Name(true))
			o.L("}")
			o.L("h.%s = &decoded", f.Name(false))
		}
	}
	o.L("default:")
	o.L("decoded, err := registry.Decode(dec, tok)")
	o.L("if err != nil {")
	o.L("return err")
	o.L("}")
	o.L("h.setNoLock(tok, decoded)")
	o.L("}")
	o.L("default:")
	o.L("return fmt.Errorf(`invalid token %%T`, tok)")
	o.L("}")
	o.L("}")
	o.L("h.raw = buf")
	o.L("return nil")
	o.L("}")

	o.LL("func (h stdHeaders) MarshalJSON() ([]byte, error) {")
	o.L("buf := pool.GetBytesBuffer()")
	o.L("defer pool.ReleaseBytesBuffer(buf)")
	o.L("buf.WriteByte('{')")
	o.L("enc := json.NewEncoder(buf)")
	o.L("for i, p := range h.makePairs() {")
	o.L("if i > 0 {")
	o.L("buf.WriteRune(',')")
	o.L("}")
	o.L("buf.WriteRune('\"')")
	o.L("buf.WriteString(p.Key.(string))")
	o.L("buf.WriteString(`\":`)")
	o.L("v := p.Value")
	o.L("switch v := v.(type) {")
	o.L("case []byte:")
	o.L("buf.WriteRune('\"')")
	o.L("buf.WriteString(base64.EncodeToString(v))")
	o.L("buf.WriteRune('\"')")
	o.L("default:")
	o.L("if err := enc.Encode(v); err != nil {")
	o.L("return nil, fmt.Errorf(`failed to encode value for field %%s: %%w`, p.Key, err)")
	o.L("}")
	o.L("buf.Truncate(buf.Len()-1)")
	o.L("}")
	o.L("}")
	o.L("buf.WriteByte('}')")
	o.L("ret := make([]byte, buf.Len())")
	o.L("copy(ret, buf.Bytes())")
	o.L("return ret, nil")
	o.L("}")

	if err := o.WriteFile(`headers_gen.go`, codegen.WithFormatCode(true)); err != nil {
		if cfe, ok := err.(codegen.CodeFormatError); ok {
			fmt.Fprint(os.Stderr, cfe.Source())
		}
		return fmt.Errorf(`failed to write to headers_gen.go: %w`, err)
	}
	return nil
}
