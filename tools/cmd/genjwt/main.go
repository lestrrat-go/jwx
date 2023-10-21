package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/goccy/go-json"
	"github.com/goccy/go-yaml"
	"github.com/lestrrat-go/codegen"
)

const (
	byteSliceType = "[]byte"
)

func main() {
	if err := _main(); err != nil {
		log.Printf("%s", err)
		os.Exit(1)
	}
}

func _main() error {
	var objectsFile = flag.String("objects", "objects.yml", "")
	flag.Parse()
	jsonSrc, err := yaml2json(*objectsFile)
	if err != nil {
		return err
	}

	var def struct {
		CommonFields codegen.FieldList `json:"common_fields"`
		Objects      []*codegen.Object `json:"objects"`
	}
	if err := json.NewDecoder(bytes.NewReader(jsonSrc)).Decode(&def); err != nil {
		return fmt.Errorf(`failed to decode %q: %w`, *objectsFile, err)
	}

	for _, object := range def.Objects {
		for _, f := range def.CommonFields {
			object.AddField(f)
		}
		object.Organize()
	}

	for _, object := range def.Objects {
		if err := generateToken(object); err != nil {
			return fmt.Errorf(`failed to generate token file %s: %w`, object.MustString(`filename`), err)
		}
	}

	for _, object := range def.Objects {
		if err := genBuilder(object); err != nil {
			return fmt.Errorf(`failed to generate builder for package %q: %w`, object.MustString(`package`), err)
		}
	}

	return nil
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
	return !(strings.HasPrefix(s, `*`) || strings.HasPrefix(s, `[]`) || strings.HasSuffix(s, `List`))
}

func generateToken(obj *codegen.Object) error {
	var buf bytes.Buffer

	o := codegen.NewOutput(&buf)
	o.L("// Code generated by tools/cmd/genjwt/main.go. DO NOT EDIT.")
	o.LL("package %s", obj.String(`package`))

	var fields = obj.Fields()

	o.LL("const (")
	for _, f := range fields {
		o.L("%sKey = %s", f.Name(true), strconv.Quote(f.JSON()))
	}
	o.L(")") // end const

	if obj.String(`package`) == "jwt" && obj.Name(false) == "stdToken" {
		o.LL("// Token represents a generic JWT token.")
		o.L("// which are type-aware (to an extent). Other claims may be accessed via the `Get`/`Set`")
		o.L("// methods but their types are not taken into consideration at all. If you have non-standard")
		o.L("// claims that you must frequently access, consider creating accessors functions")
		o.L("// like the following")
		o.L("//\n// func SetFoo(tok jwt.Token) error")
		o.L("// func GetFoo(tok jwt.Token) (*Customtyp, error)")
		o.L("//\n// Embedding jwt.Token into another struct is not recommended, because")
		o.L("// jwt.Token needs to handle private claims, and this really does not")
		o.L("// work well when it is embedded in other structure")
	}

	o.L("type %s interface {", obj.String(`interface`))
	for _, field := range fields {
		o.LL("// %s returns the value for %q field of the token", field.GetterMethod(true), field.JSON())

		rv := field.String(`getter_return_value`)
		if rv == "" {
			rv = field.Type()
		}
		o.L("%s() %s", field.GetterMethod(true), rv)
	}
	o.LL("// Get is used to extract the value of any claim, including non-standard claims, out of the token.")
	o.L("//")
	o.L("// The first argument is the name of the claim. The second argument is a pointer")
	o.L("// to a variable that will receive the value of the claim. The method returns")
	o.L("// an error if the claim does not exist, or if the value cannot be assigned to")
	o.L("// the destination variable.  Note that a field is considered to \"exist\" even if")
	o.L("// the value is empty-ish (e.g. 0, false, \"\"), as long as it is explicitly set.")
	o.L("//")
	o.L("// For standard claims, you can use the corresponding getter method, such as")
	o.L("// `Issuer()`, `Subject()`, `Audience()`, `IssuedAt()`, `NotBefore()`, `ExpiresAt()`")
	o.L("//")
	o.L("// Note that fields of JWS/JWE are NOT accessible through this method. You need")
	o.L("// to use `jws.Parse` and `jwe.Parse` to obtain the JWS/JWE message (and NOT")
	o.L("// the payload, which presumably is the JWT), and then use their `Get` methods in their respective packages")
	o.L("Get(string, interface{}) error")

	o.LL("// Set assigns a value to the corresponding field in the token. Some")
	o.L("// pre-defined fields such as `nbf`, `iat`, `iss` need their values to")
	o.L("// be of a specific type. See the other getter methods in this interface")
	o.L("// for the types of each of these fields")
	o.L("Set(string, interface{}) error")

	o.LL("// Has returns true if the specified claim has a value, even if")
	o.L("// the value is empty-ish (e.g. 0, false, \"\")  as long as it has been")
	o.L("// explicitly set.")
	o.L("Has(string) bool")

	o.L("Remove(string) error")

	var pkgPrefix string
	if obj.String(`package`) != `jwt` {
		pkgPrefix = `jwt.`
	}

	o.LL("// Options returns the per-token options associated with this token.")
	o.L("// The options set value will be copied when the token is cloned via `Clone()`")
	o.L("// but it will not survive when the token goes through marshaling/unmarshaling")
	o.L("// such as `json.Marshal` and `json.Unmarshal`")
	o.L("Options() *%sTokenOptionSet", pkgPrefix)
	o.L("Clone() (%sToken, error)", pkgPrefix)
	o.L("Keys() []string")
	o.L("}")

	o.L("type %s struct {", obj.Name(false))
	o.L("mu *sync.RWMutex")
	o.L("dc DecodeCtx // per-object context for decoding")
	o.L("options %sTokenOptionSet // per-object option", pkgPrefix)
	for _, f := range fields {
		if c := f.Comment(); c != "" {
			o.L("%s %s // %s", f.Name(false), fieldStorageType(f.Type()), c)
		} else {
			o.L("%s %s", f.Name(false), fieldStorageType(f.Type()))
		}
	}
	o.L("privateClaims map[string]interface{}")
	o.L("}") // end type Token

	o.LL("// New creates a standard token, with minimal knowledge of")
	o.L("// possible claims. Standard claims include")
	for i, field := range fields {
		o.R("%s", strconv.Quote(field.JSON()))
		switch {
		case i < len(fields)-2:
			o.R(", ")
		case i == len(fields)-2:
			o.R(" and ")
		}
	}

	o.R(".\n// Convenience accessors are provided for these standard claims")
	o.L("func New() %s {", obj.String(`interface`))
	o.L("return &%s{", obj.Name(false))
	o.L("mu: &sync.RWMutex{},")
	o.L("privateClaims: make(map[string]interface{}),")
	o.L("options: %sDefaultOptionSet(),", pkgPrefix)
	o.L("}")
	o.L("}")

	o.LL("func (t *%s) Options() *%sTokenOptionSet {", obj.Name(false), pkgPrefix)
	o.L("return &t.options")
	o.L("}")

	o.LL("func (t *%s) Has(name string) bool {", obj.Name(false))
	o.L("t.mu.RLock()")
	o.L("defer t.mu.RUnlock()")
	o.L("switch name {")
	for _, f := range obj.Fields() {
		o.L("case %sKey:", f.Name(true))
		o.L("return t.%s != nil", f.Name(false))
	}
	o.L("default:")
	o.L("_, ok := t.privateClaims[name]")
	o.L("return ok")
	o.L("}")
	o.L("}")

	o.LL("func (t *%s) Get(name string, dst interface{}) error {", obj.Name(false))
	o.L("t.mu.RLock()")
	o.L("defer t.mu.RUnlock()")
	o.L("switch name {")
	for _, f := range fields {
		o.L("case %sKey:", f.Name(true))
		o.L("if t.%s == nil {", f.Name(false))
		o.L("return fmt.Errorf(`field %%q not found`, name)")
		o.L("}")
		o.L("if err := blackmagic.AssignIfCompatible(dst, ")
		if f.Bool(`hasGet`) {
			o.R("t.%s.Get()", f.Name(false))
		} else {
			if fieldStorageTypeIsIndirect(f.Type()) {
				o.R("*(t.%s)", f.Name(false))
			} else {
				o.R("t.%s", f.Name(false))
			}
		}
		o.R("); err != nil {")
		o.L("return fmt.Errorf(`failed to assign value to dst: %%w`, err)")
		o.L("}")
		o.L("return nil")
	}
	o.L("default:")
	o.L("v, ok := t.privateClaims[name]")
	o.L("if !ok {")
	o.L("return fmt.Errorf(`field %%q not found`, name)")
	o.L("}")
	o.L("if err := blackmagic.AssignIfCompatible(dst, v); err != nil {")
	o.L("return fmt.Errorf(`failed to assign value to dst: %%w`, err)")
	o.L("}")
	o.L("return nil")
	o.L("}") // end switch name
	o.L("}") // end of Get

	o.LL("func (t *stdToken) Remove(key string) error {")
	o.L("t.mu.Lock()")
	o.L("defer t.mu.Unlock()")
	o.L("switch key {")
	for _, f := range fields {
		o.L("case %sKey:", f.Name(true))
		o.L("t.%s = nil", f.Name(false))
	}
	o.L("default:")
	o.L("delete(t.privateClaims, key)")
	o.L("}")
	o.L("return nil") // currently unused, but who knows
	o.L("}")

	o.LL("func (t *%s) Set(name string, value interface{}) error {", obj.Name(false))
	o.L("t.mu.Lock()")
	o.L("defer t.mu.Unlock()")
	o.L("return t.setNoLock(name, value)")
	o.L("}")

	o.LL("func (t *%s) DecodeCtx() DecodeCtx {", obj.Name(false))
	o.L("t.mu.RLock()")
	o.L("defer t.mu.RUnlock()")
	o.L("return t.dc")
	o.L("}")

	o.LL("func (t *%s) SetDecodeCtx(v DecodeCtx) {", obj.Name(false))
	o.L("t.mu.Lock()")
	o.L("defer t.mu.Unlock()")
	o.L("t.dc = v")
	o.L("}")

	o.LL("func (t *%s) setNoLock(name string, value interface{}) error {", obj.Name(false))
	o.L("switch name {")
	for _, f := range fields {
		keyName := f.Name(true) + "Key"
		o.L("case %s:", keyName)
		if f.Name(false) == `algorithm` {
			o.L("switch v := value.(type) {")
			o.L("case string:")
			o.L("t.algorithm = &v")
			o.L("case fmt.Stringer:")
			o.L("tmp := v.String()")
			o.L("t.algorithm = &tmp")
			o.L("default:")
			o.L("return fmt.Errorf(`invalid type for %%s key: %%T`, %s, value)", keyName)
			o.L("}")
			o.L("return nil")
		} else if f.Bool(`hasAccept`) {
			if IsPointer(f) {
				o.L("var acceptor %s", strings.TrimPrefix(f.Type(), "*"))
			} else {
				o.L("var acceptor %s", f.Type())
			}

			o.L("if err := acceptor.Accept(value); err != nil {")
			o.L("return fmt.Errorf(`invalid value for %%s key: %%w`, %s, err)", keyName)
			o.L("}") // end if err := t.%s.Accept(value)
			if fieldStorageTypeIsIndirect(f.Type()) || IsPointer(f) {
				o.L("t.%s = &acceptor", f.Name(false))
			} else {
				o.L("t.%s = acceptor", f.Name(false))
			}
			o.L("return nil")
		} else {
			o.L("if v, ok := value.(%s); ok {", f.Type())
			if fieldStorageTypeIsIndirect(f.Type()) {
				o.L("t.%s = &v", f.Name(false))
			} else {
				o.L("t.%s = v", f.Name(false))
			}
			o.L("return nil")
			o.L("}") // end if v, ok := value.(%s)
			o.L("return fmt.Errorf(`invalid value for %%s key: %%T`, %s, value)", keyName)
		}
	}
	o.L("default:")
	o.L("if t.privateClaims == nil {")
	o.L("t.privateClaims = map[string]interface{}{}")
	o.L("}") // end if t.privateClaims == nil
	o.L("t.privateClaims[name] = value")
	o.L("}") // end switch name
	o.L("return nil")
	o.L("}") // end func (t *%s) Set(name string, value interface{})

	for _, f := range fields {
		rv := f.String(`getter_return_value`)
		if rv == "" {
			rv = f.Type()
		}
		o.LL("func (t *%s) %s() ", obj.Name(false), f.GetterMethod(true))
		if rv != "" {
			o.R("%s", rv)
		} else if IsPointer(f) && f.Bool(`noDeref`) {
			o.R("%s", f.Type())
		} else {
			o.R("%s", PointerElem(f))
		}
		o.R(" {")
		o.L("t.mu.RLock()")
		o.L("defer t.mu.RUnlock()")

		if f.Bool(`hasGet`) {
			o.L("if t.%s != nil {", f.Name(false))
			o.L("return t.%s.Get()", f.Name(false))
			o.L("}")
			o.L("return %s", codegen.ZeroVal(rv))
		} else if !IsPointer(f) {
			if fieldStorageTypeIsIndirect(f.Type()) {
				o.L("if t.%s != nil {", f.Name(false))
				o.L("return *(t.%s)", f.Name(false))
				o.L("}")
				o.L("return %s", codegen.ZeroVal(rv))
			} else {
				o.L("return t.%s", f.Name(false))
			}
		} else {
			o.L("return t.%s", f.Name(false))
		}
		o.L("}") // func (h *stdHeaders) %s() %s
	}

	o.LL("func (t *%s) PrivateClaims() map[string]interface{} {", obj.Name(false))
	o.L("t.mu.RLock()")
	o.L("defer t.mu.RUnlock()")
	o.L("return t.privateClaims")
	o.L("}")

	o.LL("func (t *stdToken) UnmarshalJSON(buf []byte) error {")
	o.L("t.mu.Lock()")
	o.L("defer t.mu.Unlock()")
	for _, f := range fields {
		o.L("t.%s = nil", f.Name(false))
	}

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

	for _, f := range fields {
		if f.Type() == "string" {
			o.L("case %sKey:", f.Name(true))
			o.L("if err := json.AssignNextStringToken(&t.%s, dec); err != nil {", f.Name(false))
			o.L("return fmt.Errorf(`failed to decode value for key %%s: %%w`, %sKey, err)", f.Name(true))
			o.L("}")
		} else if f.Type() == byteSliceType {
			o.L("case %sKey:", f.Name(true))
			o.L("if err := json.AssignNextBytesToken(&t.%s, dec); err != nil {", f.Name(false))
			o.L("return fmt.Errorf(`failed to decode value for key %%s: %%w`, %sKey, err)", f.Name(true))
			o.L("}")
		} else if f.Type() == "types.StringList" || strings.HasPrefix(f.Type(), "[]") {
			o.L("case %sKey:", f.Name(true))
			o.L("var decoded %s", f.Type())
			o.L("if err := dec.Decode(&decoded); err != nil {")
			o.L("return fmt.Errorf(`failed to decode value for key %%s: %%w`, %sKey, err)", f.Name(true))
			o.L("}")
			o.L("t.%s = decoded", f.Name(false))
		} else {
			o.L("case %sKey:", f.Name(true))
			if IsPointer(f) {
				o.L("var decoded %s", PointerElem(f))
			} else {
				o.L("var decoded %s", f.Type())
			}
			o.L("if err := dec.Decode(&decoded); err != nil {")
			o.L("return fmt.Errorf(`failed to decode value for key %%s: %%w`, %sKey, err)", f.Name(true))
			o.L("}")
			o.L("t.%s = &decoded", f.Name(false))
		}
	}
	o.L("default:")
	// This looks like bad code, but we're unrolling things for maximum
	// runtime efficiency
	o.L("if dc := t.dc; dc != nil {")
	o.L("if localReg := dc.Registry(); localReg != nil {")
	o.L("decoded, err := localReg.Decode(dec, tok)")
	o.L("if err == nil {")
	o.L("t.setNoLock(tok, decoded)")
	o.L("continue")
	o.L("}")
	o.L("}")
	o.L("}")

	o.L("decoded, err := registry.Decode(dec, tok)")
	o.L("if err == nil {")
	o.L("t.setNoLock(tok, decoded)")
	o.L("continue")
	o.L("}")
	o.L("return fmt.Errorf(`could not decode field %%s: %%w`, tok, err)")
	o.L("}")
	o.L("default:")
	o.L("return fmt.Errorf(`invalid token %%T`, tok)")
	o.L("}")
	o.L("}")

	o.L("return nil")
	o.L("}")

	o.LL("func (t *%s) Keys() []string {", obj.Name(false))
	o.L("t.mu.RLock()")
	o.L("defer t.mu.RUnlock()")
	o.L("keys := make([]string, 0, %d+len(t.privateClaims))", len(obj.Fields()))
	for _, f := range obj.Fields() {
		keyName := f.Name(true) + "Key"
		o.L("if t.%s != nil {", f.Name(false))
		o.L("keys = append(keys, %s)", keyName)
		o.L("}")
	}
	o.L("for k := range t.privateClaims {")
	o.L("keys = append(keys, k)")
	o.L("}")
	o.L("return keys")
	o.L("}")
	var numericDateFields []codegen.Field
	for _, field := range fields {
		if field.Type() == "types.NumericDate" {
			numericDateFields = append(numericDateFields, field)
		}
	}

	o.LL("type claimPair struct { Name string; Value interface{} }")
	o.LL("var claimPairPool = sync.Pool{")
	o.L("New: func() interface{} {")
	o.L("return make([]claimPair, 0, %d)", len(fields))
	o.L("},")
	o.L("}")
	o.LL("func getClaimPairList() []claimPair {")
	o.L("return claimPairPool.Get().([]claimPair)")
	o.L("}")
	o.LL("func putClaimPairList(list []claimPair) {")
	o.L("list = list[:0]")
	o.L("claimPairPool.Put(list)")
	o.L("}")

	o.LL("// makePairs creates a list of claimPair objects that are sorted by")
	o.L("// their key names. The key names are always their JSON names, and")
	o.L("// the values are already JSON encoded.")
	o.L("// Because makePairs needs to allocate a slice, it _slows_ down ")
	o.L("// marshaling of the token to JSON. The upside is that it allows us to")
	o.L("// marshal the token keys in a deterministic order.")
	o.L("// Do we really need it...? Well, technically we don't, but it's so")
	o.L("// much nicer to have this to make the example tests actually work")
	o.L("// deterministically. Also if for whatever reason this becomes a")
	o.L("// performance issue, we can always/ add a flag to use a more _optimized_ code path.")
	o.L("//")
	o.L("// The caller is responsible to call putClaimPairList() to return the")
	o.L("// allocated slice back to the pool.")
	o.LL("func (t *%s) makePairs() ([]claimPair, error) {", obj.Name(false))
	o.L("pairs := getClaimPairList()")
	for _, f := range fields {
		o.L("if t.%s != nil {", f.Name(false))
		if f.Name(false) == `audience` {
			o.L("buf, err := json.MarshalAudience(t.audience, t.options.IsEnabled(%sFlattenAudience))", pkgPrefix)
			o.L("if err != nil {")
			o.L("return nil, fmt.Errorf(`failed to encode \"aud\": %%w`, err)")
			o.L("}")
			o.L("pairs = append(pairs, claimPair{Name: %sKey, Value: buf})", f.Name(true))
		} else if f.Type() == "types.NumericDate" {
			o.L("buf, err := json.Marshal(t.%s.Unix())", f.Name(false))
			o.L("if err != nil {")
			o.L("return nil, fmt.Errorf(`failed to encode %q: %%w`, err)", f.JSON())
			o.L("}")
			o.L("pairs = append(pairs, claimPair{Name: %sKey, Value: buf})", f.Name(true))
		} else if f.Type() == "[]byte" {
			o.L("buf := base64.EncodeToString(t.%s))", f.Name(false))
			o.L("pairs = append(pairs, claimPair{Name: %sKey, Value: buf})", f.Name(true))
		} else {
			o.L("buf, err := json.Marshal(*(t.%s))", f.Name(false))
			o.L("if err != nil {")
			o.L("return nil, fmt.Errorf(`failed to encode field %q: %%w`, err)", f.JSON())
			o.L("}")
			o.L("pairs = append(pairs, claimPair{Name: %sKey, Value: buf})", f.Name(true))
		}
		o.L("}")
	}

	o.L("for k, v := range t.privateClaims {")
	o.L("buf, err := json.Marshal(v)")
	o.L("if err != nil {")
	o.L("return nil, fmt.Errorf(`failed to encode field %%q: %%w`, k, err)")
	o.L("}")
	o.L("pairs = append(pairs, claimPair{Name: k, Value: buf})")
	o.L("}")
	o.LL("sort.Slice(pairs, func(i, j int) bool {")
	o.L("return pairs[i].Name < pairs[j].Name")
	o.L("})")
	o.LL("return pairs, nil")
	o.L("}")

	o.LL("func (t %s) MarshalJSON() ([]byte, error) {", obj.Name(false))
	o.L("buf := pool.GetBytesBuffer()")
	o.L("defer pool.ReleaseBytesBuffer(buf)")
	o.L("pairs, err := t.makePairs()")
	o.L("if err != nil {")
	o.L("return nil, fmt.Errorf(`failed to make pairs: %%w`, err)")
	o.L("}")
	o.L("buf.WriteByte('{')")
	o.LL("for i, pair := range pairs {")
	o.L("if i > 0 {")
	o.L("buf.WriteByte(',')")
	o.L("}")
	o.L(`fmt.Fprintf(buf, "%%q: %%s", pair.Name, pair.Value)`)
	o.L("}")
	o.L("buf.WriteByte('}')")
	o.L("ret := make([]byte, buf.Len())")
	o.L("copy(ret, buf.Bytes())")
	o.L("putClaimPairList(pairs)")
	o.L("return ret, nil")
	o.L("}")

	if err := o.WriteFile(obj.MustString(`filename`), codegen.WithFormatCode(true)); err != nil {
		if cfe, ok := err.(codegen.CodeFormatError); ok {
			fmt.Fprint(os.Stderr, cfe.Source())
		}
		return fmt.Errorf(`failed to write to %s: %w`, obj.MustString(`filename`), err)
	}
	return nil
}

func genBuilder(obj *codegen.Object) error {
	var buf bytes.Buffer
	pkg := obj.MustString(`package`)
	o := codegen.NewOutput(&buf)
	o.L("// Code generated by tools/cmd/genjwt/main.go. DO NOT EDIT.")
	o.LL("package %s", pkg)

	o.LL("// Builder is a convenience wrapper around the New() constructor")
	o.L("// and the Set() methods to assign values to Token claims.")
	o.L("// Users can successively call Claim() on the Builder, and have it")
	o.L("// construct the Token when Build() is called. This alleviates the")
	o.L("// need for the user to check for the return value of every single")
	o.L("// Set() method call.")
	o.L("// Note that each call to Claim() overwrites the value set from the")
	o.L("// previous call.")
	o.L("type Builder struct {")
	o.L("mu sync.Mutex")
	o.L("claims map[string]interface{}")
	o.L("}")

	o.LL("func NewBuilder() *Builder {")
	o.L("return &Builder{}")
	o.L("}")

	o.LL("func (b *Builder) init() {")
	o.L("if b.claims == nil {")
	o.L("b.claims = make(map[string]interface{})")
	o.L("}")
	o.L("}")

	o.LL("func (b *Builder) Claim(name string, value interface{}) *Builder {")
	o.L("b.mu.Lock()")
	o.L("defer b.mu.Unlock()")
	o.L("b.init()")
	o.L("b.claims[name] = value")
	o.L("return b")
	o.L("}")

	for _, f := range obj.Fields() {
		ftyp := f.Type()
		if ftyp == "types.NumericDate" {
			ftyp = "time.Time"
		} else if ftyp == "types.StringList" {
			ftyp = "[]string"
		}
		o.LL("func (b *Builder) %s(v %s) *Builder {", f.Name(true), ftyp)
		o.L("return b.Claim(%sKey, v)", f.Name(true))
		o.L("}")
	}

	o.LL("// Build creates a new token based on the claims that the builder has received")
	o.L("// so far. If a claim cannot be set, then the method returns a nil Token with")
	o.L("// a en error as a second return value")
	o.L("//")
	o.L("// Once `Build()` is called, all claims are cleared from the Builder, and the")
	o.L("// Builder can be reused to build another token")
	o.L("func (b *Builder) Build() (Token, error) {")
	o.L("b.mu.Lock()")
	o.L("claims := b.claims")
	o.L("b.claims = nil")
	o.L("b.mu.Unlock()")
	o.L("tok := New()")
	o.L("for k, v := range claims {")
	o.L("if err := tok.Set(k, v); err != nil {")
	o.L("return nil, fmt.Errorf(`failed to set claim %%q: %%w`, k, err)")
	o.L("}")
	o.L("}")
	o.L("return tok, nil")
	o.L("}")

	fn := "builder_gen.go"
	if pkg != "jwt" {
		fn = filepath.Join(pkg, fn)
	}
	if err := o.WriteFile(fn, codegen.WithFormatCode(true)); err != nil {
		if cfe, ok := err.(codegen.CodeFormatError); ok {
			fmt.Fprint(os.Stderr, cfe.Source())
		}
		return fmt.Errorf(`failed to write to %s: %w`, fn, err)
	}
	return nil
}
