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
	codegen.RegisterZeroVal(`jwa.SignatureAlgorithm`, `jwa.EmptySignatureAlgorithm()`)

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

	o.LL("// Headers describe a standard JWS Header set. It is part of the JWS message")
	o.L("// and is used to represet both Public or Protected headers, which in turn")
	o.L("// can be found in each Signature object. If you are not sure how this works,")
	o.L("// it is strongly recommended that you read RFC7515, especially the section")
	o.L("// that describes the full JSON serialization format of JWS messages.")
	o.L("//")
	o.L("// In most cases, you likely want to use the protected headers, as this is part of the signed content.")
	o.L("type Headers interface {")
	// These are the basic values that most jws have
	for _, f := range obj.Fields() {
		if f.Bool(`noDeref`) {
			o.L("%s() (%s, bool)", f.GetterMethod(true), f.Type())
		} else {
			o.L("%s() (%s, bool)", f.GetterMethod(true), PointerElem(f))
		}
	}

	o.L("Copy(Headers) error")
	o.L("Merge(Headers) (Headers, error)")

	// These are used to access a single element by key name
	o.L("// Get is used to extract the value of any field, including non-standard fields, out of the header.")
	o.L("//")
	o.L("// The first argument is the name of the field. The second argument is a pointer")
	o.L("// to a variable that will receive the value of the field. The method returns")
	o.L("// an error if the field does not exist, or if the value cannot be assigned to")
	o.L("// the destination variable. Note that a field is considered to \"exist\" even if")
	o.L("// the value is empty-ish (e.g. 0, false, \"\"), as long as it is explicitly set.")
	o.L("Get(string, interface{}) error")
	o.L("Set(string, interface{}) error")
	o.L("Remove(string) error")
	o.L("// Has returns true if the specified header has a value, even if")
	o.L("// the value is empty-ish (e.g. 0, false, \"\")  as long as it has been")
	o.L("// explicitly set.")
	o.L("Has(string) bool")

	o.L("Keys() []string")
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
		o.LL("func (h *stdHeaders) %s() (%s, bool) {", f.GetterMethod(true), f.Type())
		o.L("h.mu.RLock()")
		o.L("defer h.mu.RUnlock()")
		if fieldStorageTypeIsIndirect(f.Type()) {
			o.L("if h.%s == nil {", f.Name(false))
			o.L("return %s, false", codegen.ZeroVal(f.Type()))
			o.L("}")
			o.L("return *(h.%s), true", f.Name(false))
		} else {
			o.L("return h.%s, true", f.Name(false))
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
		if f.Name(true) == `Algorithm` {
			o.L(`alg, err := jwa.KeyAlgorithmFrom(value)`)
			o.L(`if err != nil {`)
			o.L(`return fmt.Errorf("invalid value for %%s key: %%w", %sKey, err)`, f.Name(true))
			o.L(`}`)
			o.L(`if salg, ok := alg.(jwa.SignatureAlgorithm); ok {`)
			o.L(`h.%s = &salg`, f.Name(false))
			o.L(`return nil`)
			o.L(`}`)
			o.L(`return fmt.Errorf("expecte jwa.SignatureAlgorithm, received %%T", alg)`)
		} else if f.Bool(`hasAccept`) {
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

	o.LL("func (h *stdHeaders) Keys() []string {")
	o.L("h.mu.RLock()")
	o.L("defer h.mu.RUnlock()")
	o.L("keys := make([]string, 0, %d+len(h.privateParams))", len(obj.Fields()))
	for _, f := range obj.Fields() {
		keyName := f.Name(true) + "Key"
		o.L("if h.%s != nil {", f.Name(false))
		o.L("keys = append(keys, %s)", keyName)
		o.L("}")
	}
	o.L("for k := range h.privateParams {")
	o.L("keys = append(keys, k)")
	o.L("}")
	o.L("return keys")
	o.L("}")

	o.LL("func (h stdHeaders) MarshalJSON() ([]byte, error) {")
	o.L("h.mu.RLock()")
	o.L("data := make(map[string]interface{})")
	o.L("keys := make([]string, 0, %d+len(h.privateParams))", len(obj.Fields()))
	for _, f := range obj.Fields() {
		o.L("if h.%s != nil {", f.Name(false))
		if fieldStorageTypeIsIndirect(f.Type()) {
			o.L("data[%sKey] = *(h.%s)", f.Name(true), f.Name(false))
		} else {
			o.L("data[%sKey] = h.%s", f.Name(true), f.Name(false))
		}
		o.L("keys = append(keys, %sKey)", f.Name(true))
		o.L("}")
	}
	o.L("for k, v := range h.privateParams {")
	o.L("data[k] = v")
	o.L("keys = append(keys, k)")
	o.L("}")
	o.L("h.mu.RUnlock()")
	o.L("sort.Strings(keys)")

	o.L("buf := pool.GetBytesBuffer()")
	o.L("defer pool.ReleaseBytesBuffer(buf)")
	o.L("enc := json.NewEncoder(buf)")

	o.L("buf.WriteByte('{')")
	o.L("for i, k := range keys {")
	o.L("if i > 0 {")
	o.L("buf.WriteRune(',')")
	o.L("}")
	o.L("buf.WriteRune('\"')")
	o.L("buf.WriteString(k)")
	o.L("buf.WriteString(`\":`)")
	o.L("switch v := data[k].(type) {")
	o.L("case []byte:")
	o.L("buf.WriteRune('\"')")
	o.L("buf.WriteString(base64.EncodeToString(v))")
	o.L("buf.WriteRune('\"')")
	o.L("default:")
	o.L("if err := enc.Encode(v); err != nil {")
	o.L("return nil, fmt.Errorf(`failed to encode value for field %%s: %%w`, k, err)")
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
