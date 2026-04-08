package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/goccy/go-json"
	"github.com/lestrrat-go/codegen"
	"github.com/lestrrat-go/jwx/v4/internal/jwxcodegen"
)

func runJWT(args []string) error {
	fs := flag.NewFlagSet("generate-jwt", flag.ContinueOnError)
	objectsFile := fs.String("objects", "objects.yml", "")
	if err := fs.Parse(args); err != nil {
		return err
	}

	jsonSrc, err := jwxcodegen.YAML2JSON(*objectsFile)
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

func computePkgPrefix(obj *codegen.Object) string {
	if obj.String("package") != "jwt" {
		return "jwt."
	}
	return ""
}

func tokenKeyName(f codegen.Field) string {
	return f.Name(true) + "Key"
}

func makeTokenCaseConfig(obj *codegen.Object) jwxcodegen.CaseConfig {
	return jwxcodegen.CaseConfig{
		Fields:       obj.Fields(),
		KeyName:      tokenKeyName,
		ReceiverName: "t",
	}
}

func generateTokenConstants(o *codegen.Output, obj *codegen.Object) {
	fields := obj.Fields()

	o.LL("const (")
	for _, f := range fields {
		o.L("%sKey = %s", f.Name(true), strconv.Quote(f.JSON()))
	}
	o.L(")") // end const

	// Create a stdClaimNames array
	o.LL("// stdClaimNames is a list of all standard claim names defined in the JWT specification.")
	o.L("var stdClaimNames = []string{")
	for i, f := range fields {
		if i > 0 {
			o.R(", ")
		}
		o.R("%sKey", f.Name(true))
	}
	o.R("}")
}

func generateTokenInterface(o *codegen.Output, obj *codegen.Object, pkgPrefix string) {
	fields := obj.Fields()

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
	for i, field := range fields {
		if i > 0 {
			o.L("")
		}
		o.L("// %s returns the value for %q field of the token", field.GetterMethod(true), field.JSON())
		rv := field.String(`getter_return_value`)
		if rv == "" {
			rv = field.Type()
		}
		o.L("%s() (%s, bool)", field.GetterMethod(true), rv)
	}
	o.LL("// Field returns the value of a claim by name, along with a boolean indicating")
	o.L("// whether the claim was found. For standard claims, you can also use the")
	o.L("// corresponding getter method, such as `Issuer()`, `Subject()`, etc.")
	o.L("// For type-safe access to claims, use the `jwt.Get[T]()` generic accessor.")
	o.L("Field(string) (any, bool)")

	o.LL("// Set assigns a value to the corresponding field in the token. Some")
	o.L("// pre-defined fields such as `nbf`, `iat`, `iss` need their values to")
	o.L("// be of a specific type. See the other getter methods in this interface")
	o.L("// for the types of each of these fields")
	o.L("Set(string, any) error")

	o.LL("// Has returns true if the specified claim has a value, even if")
	o.L("// the value is empty-ish (e.g. 0, false, \"\")  as long as it has been")
	o.L("// explicitly set.")
	o.L("Has(string) bool")

	o.L("Remove(string) error")

	o.LL("// Options returns the per-token options associated with this token.")
	o.L("// The options set value will be copied when the token is cloned via `Clone()`")
	o.L("// but it will not survive when the token goes through marshaling/unmarshaling")
	o.L("// such as `json.Marshal` and `json.Unmarshal`")
	o.L("Options() *%sTokenOptionSet", pkgPrefix)
	o.L("Clone() (%sToken, error)", pkgPrefix)
	o.L("Keys() []string")
	o.L("// Claims returns an iterator over all claims (standard and private) in the token.")
	o.L("Claims() iter.Seq2[string, any]")
	o.L("}")
}

func generateTokenStruct(o *codegen.Output, obj *codegen.Object, pkgPrefix string) {
	fields := obj.Fields()

	o.L("type %s struct {", obj.Name(false))
	o.L("mu sync.RWMutex")
	o.L("dc DecodeCtx // per-object context for decoding")
	o.L("options %sTokenOptionSet // per-object option", pkgPrefix)
	for _, f := range fields {
		if c := f.Comment(); c != "" {
			o.L("%s %s // %s", f.Name(false), jwxcodegen.FieldStorageType(f), c)
		} else {
			o.L("%s %s", f.Name(false), jwxcodegen.FieldStorageType(f))
		}
	}
	o.L("privateClaims map[string]any")
	o.L("}") // end type Token
}

func generateTokenConstructor(o *codegen.Output, obj *codegen.Object, pkgPrefix string) {
	fields := obj.Fields()

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
	o.L("privateClaims: make(map[string]any),")
	o.L("options: %sDefaultOptionSet(),", pkgPrefix)
	o.L("}")
	o.L("}")

	o.LL("func (t *%s) Options() *%sTokenOptionSet {", obj.Name(false), pkgPrefix)
	o.L("t.mu.RLock()")
	o.L("defer t.mu.RUnlock()")
	o.L("return &t.options")
	o.L("}")
}

func generateTokenHas(o *codegen.Output, obj *codegen.Object) {
	o.LL("func (t *%s) Has(name string) bool {", obj.Name(false))
	o.L("t.mu.RLock()")
	o.L("defer t.mu.RUnlock()")
	o.L("switch name {")
	jwxcodegen.GenerateHasCases(o, makeTokenCaseConfig(obj))
	o.L("default:")
	o.L("_, ok := t.privateClaims[name]")
	o.L("return ok")
	o.L("}")
	o.L("}")
}

func generateTokenFieldAndGet(o *codegen.Output, obj *codegen.Object) {
	o.LL("func (t *%s) Field(name string) (any, bool) {", obj.Name(false))
	o.L("t.mu.RLock()")
	o.L("defer t.mu.RUnlock()")
	o.L("switch name {")
	jwxcodegen.GenerateFieldCases(o, makeTokenCaseConfig(obj), jwxcodegen.FieldStorageTypeIsIndirect)
	o.L("default:")
	o.L("v, ok := t.privateClaims[name]")
	o.L("return v, ok")
	o.L("}") // end switch name
	o.L("}") // end of Field
}

func generateTokenRemove(o *codegen.Output, obj *codegen.Object) {
	o.LL("func (t *stdToken) Remove(key string) error {")
	o.L("t.mu.Lock()")
	o.L("defer t.mu.Unlock()")
	o.L("switch key {")
	jwxcodegen.GenerateRemoveCases(o, makeTokenCaseConfig(obj))
	o.L("default:")
	o.L("delete(t.privateClaims, key)")
	o.L("}")
	o.L("return nil") // currently unused, but who knows
	o.L("}")
}

func generateTokenSet(o *codegen.Output, obj *codegen.Object) {
	o.LL("func (t *%s) Set(name string, value any) error {", obj.Name(false))
	o.L("t.mu.Lock()")
	o.L("defer t.mu.Unlock()")
	o.L("return t.setNoLock(name, value)")
	o.L("}")

	jwxcodegen.GenerateDecodeCtx(o, jwxcodegen.DecodeCtxConfig{
		ReceiverName:  "t",
		StructName:    obj.Name(false),
		DecodeCtxType: "DecodeCtx",
	})

	// Build skip set for fields with special handling in setNoLock
	skip := make(map[string]struct{})
	for _, f := range obj.Fields() {
		if f.Name(false) == "algorithm" {
			skip["algorithm"] = struct{}{}
		}
	}

	cfg := makeTokenCaseConfig(obj)
	cfg.Skip = skip

	o.LL("func (t *%s) setNoLock(name string, value any) error {", obj.Name(false))
	o.L("switch name {")

	// Emit algorithm special case inline if present
	for _, f := range obj.Fields() {
		if f.Name(false) == "algorithm" {
			keyName := f.Name(true) + "Key"
			o.L("case %s:", keyName)
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
		}
	}

	jwxcodegen.GenerateSetCases(o, cfg, jwxcodegen.FieldStorageTypeIsIndirect)
	o.L("default:")
	o.L("if t.privateClaims == nil {")
	o.L("t.privateClaims = map[string]any{}")
	o.L("}") // end if t.privateClaims == nil
	o.L("t.privateClaims[name] = value")
	o.L("}") // end switch name
	o.L("return nil")
	o.L("}") // end func (t *%s) Set(name string, value any)
}

func generateTokenGetters(o *codegen.Output, obj *codegen.Object) {
	fields := obj.Fields()

	for _, f := range fields {
		rv := f.String(`getter_return_value`)
		if rv == "" {
			rv = f.Type()
		}
		o.LL("func (t *%s) %s() (", obj.Name(false), f.GetterMethod(true))
		if rv != "" {
			o.R("%s", rv)
		} else if jwxcodegen.IsPointer(f) && f.Bool(`noDeref`) {
			o.R("%s", f.Type())
		} else {
			o.R("%s", jwxcodegen.PointerElem(f))
		}
		o.R(", bool) {")
		o.L("t.mu.RLock()")
		o.L("defer t.mu.RUnlock()")

		if f.Bool(`hasGet`) {
			o.L("if t.%s != nil {", f.Name(false))
			o.L("return t.%s.Get(), true", f.Name(false))
			o.L("}")
			o.L("return %s, false", codegen.ZeroVal(rv))
		} else if !jwxcodegen.IsPointer(f) {
			if jwxcodegen.FieldStorageTypeIsIndirect(f) {
				o.L("if t.%s != nil {", f.Name(false))
				o.L("return *(t.%s), true", f.Name(false))
				o.L("}")
				o.L("return %s, false", codegen.ZeroVal(rv))
			} else {
				o.L("return t.%s, true", f.Name(false))
			}
		} else {
			o.L("if t.%s != nil {", f.Name(false))
			o.L("return t.%s, true", f.Name(false))
			o.L("}")
			o.L("return nil, false")
		}
		o.L("}") // func (h *stdHeaders) %s() %s
	}
}

func generateTokenPrivateClaims(o *codegen.Output, obj *codegen.Object) {
	o.LL("func (t *%s) PrivateClaims() map[string]any {", obj.Name(false))
	o.L("t.mu.RLock()")
	o.L("defer t.mu.RUnlock()")
	o.L("return t.privateClaims")
	o.L("}")
}

func generateTokenUnmarshalJSON(o *codegen.Output, obj *codegen.Object) {
	fields := obj.Fields()

	o.LL("func (t *stdToken) UnmarshalJSON(buf []byte) error {")
	o.L("t.mu.Lock()")
	o.L("defer t.mu.Unlock()")
	for _, f := range fields {
		o.L("t.%s = nil", f.Name(false))
	}

	o.L("dec := json.NewDecoder(bytes.NewReader(buf))")
	o.L("tok, err := dec.ReadToken()")
	o.L("if err != nil {")
	o.L("return fmt.Errorf(`error reading token: %%w`, err)")
	o.L("}")
	o.L("if tok.Kind() != '{' {")
	o.L("return fmt.Errorf(`expected '{' but got '%%c'`, tok.Kind())")
	o.L("}")
	o.L("for dec.PeekKind() != '}' {")
	o.L("tok, err := dec.ReadToken()")
	o.L("if err != nil {")
	o.L("return fmt.Errorf(`error reading token: %%w`, err)")
	o.L("}")
	o.L("switch tok.String() {")

	jwxcodegen.GenerateUnmarshalCases(o, makeTokenCaseConfig(obj), "t.dc")

	o.L("default:")
	o.L("fieldName := tok.String()")
	// This looks like bad code, but we're unrolling things for maximum
	// runtime efficiency
	o.L("raw, err := dec.ReadValue()")
	o.L("if err != nil {")
	o.L("return fmt.Errorf(`could not read value for field %%s: %%w`, fieldName, err)")
	o.L("}")
	o.L("if dc := t.dc; dc != nil {")
	o.L("if localReg := dc.Registry(); localReg != nil {")
	o.L("decoded, err := localReg.Decode(fieldName, raw)")
	o.L("if err == nil {")
	o.L("t.setNoLock(fieldName, decoded)")
	o.L("continue")
	o.L("}")
	o.L("}")
	o.L("}")

	o.L("decoded, err := registry.Decode(fieldName, raw)")
	o.L("if err == nil {")
	o.L("t.setNoLock(fieldName, decoded)")
	o.L("continue")
	o.L("}")
	o.L("return fmt.Errorf(`could not decode field %%s: %%w`, fieldName, err)")
	o.L("}")
	o.L("}")
	o.L("// consume closing '}'")
	o.L("if _, err := dec.ReadToken(); err != nil {")
	o.L("return fmt.Errorf(`error reading closing token: %%w`, err)")
	o.L("}")

	o.L("return nil")
	o.L("}")
}

func generateTokenKeys(o *codegen.Output, obj *codegen.Object) {
	jwxcodegen.GenerateKeysMethod(o, jwxcodegen.KeysConfig{
		MethodConfig: jwxcodegen.MethodConfig{
			ReceiverName:       "t",
			StructName:         obj.Name(false),
			Fields:             obj.Fields(),
			KeyName:            tokenKeyName,
			PrivateParamsField: "privateClaims",
		},
	})
}

func generateTokenClaims(o *codegen.Output, obj *codegen.Object) {
	// Generate Claims() iter.Seq2[string, any] method
	o.LL("func (t *%s) Claims() iter.Seq2[string, any] {", obj.Name(false))
	o.L("return func(yield func(string, any) bool) {")
	o.L("t.mu.RLock()")
	o.L("defer t.mu.RUnlock()")
	for _, f := range obj.Fields() {
		keyName := f.Name(true) + "Key"
		o.L("if t.%s != nil {", f.Name(false))
		if jwxcodegen.FieldStorageTypeIsIndirect(f) {
			o.L("if !yield(%s, *(t.%s)) { return }", keyName, f.Name(false))
		} else {
			o.L("if !yield(%s, t.%s) { return }", keyName, f.Name(false))
		}
		o.L("}")
	}
	o.L("for k, v := range t.privateClaims {")
	o.L("if !yield(k, v) { return }")
	o.L("}")
	o.L("}")
	o.L("}")
}

func generateTokenCloneFrom(o *codegen.Output, obj *codegen.Object) {
	jwxcodegen.GenerateCloneFrom(o, jwxcodegen.CloneConfig{
		MethodConfig: jwxcodegen.MethodConfig{
			StructName:                 obj.Name(false),
			Fields:                     obj.Fields(),
			PrivateParamsField:         "privateClaims",
			FieldStorageTypeIsIndirect: jwxcodegen.FieldStorageTypeIsIndirect,
		},
		ExtraFieldsToCopy: []jwxcodegen.ExtraCloneField{
			{Name: "options", DirectCopy: true},
		},
		InitPrivateParams: true,
	})
}

func generateTokenMakePairsAndMarshal(o *codegen.Output, obj *codegen.Object, pkgPrefix string) {
	fields := obj.Fields()

	o.LL("type claimPair struct { Name string; Value any }")

	o.LL("var claimPairPool = sync.Pool{")
	o.L("New: func() any {")
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

	o.LL("func (t *%s) makePairs() []claimPair {", obj.Name(false))
	o.L("pairs := getClaimPairList()")
	o.L("t.mu.RLock()")
	o.L("defer t.mu.RUnlock()")
	for _, f := range fields {
		o.L("if t.%s != nil {", f.Name(false))
		if f.Name(false) == `audience` {
			o.L("pairs = append(pairs, claimPair{Name: %sKey, Value: t.audience})", f.Name(true))
		} else if f.Type() == "types.NumericDate" {
			o.L("pairs = append(pairs, claimPair{Name: %sKey, Value: t.%s.Unix()})", f.Name(true), f.Name(false))
		} else if f.Type() == "[]byte" {
			o.L("pairs = append(pairs, claimPair{Name: %sKey, Value: base64.EncodeToString(t.%s)})", f.Name(true), f.Name(false))
		} else {
			if jwxcodegen.FieldStorageTypeIsIndirect(f) {
				o.L("pairs = append(pairs, claimPair{Name: %sKey, Value: *(t.%s)})", f.Name(true), f.Name(false))
			} else {
				o.L("pairs = append(pairs, claimPair{Name: %sKey, Value: t.%s})", f.Name(true), f.Name(false))
			}
		}
		o.L("}")
	}

	o.L("for k, v := range t.privateClaims {")
	o.L("pairs = append(pairs, claimPair{Name: k, Value: v})")
	o.L("}")
	o.LL("slices.SortFunc(pairs, func(a, b claimPair) int {")
	o.L("return cmp.Compare(a.Name, b.Name)")
	o.L("})")
	o.LL("return pairs")
	o.L("}")

	o.LL("func (t *%s) MarshalJSON() ([]byte, error) {", obj.Name(false))
	o.L("buf := pool.BytesBuffer().Get()")
	o.L("defer pool.BytesBuffer().Put(buf)")
	o.L("pairs := t.makePairs()")
	o.L("buf.WriteByte('{')")
	o.L("for i, pair := range pairs {")
	o.L("if i > 0 { buf.WriteByte(',') }")
	o.L("fmt.Fprintf(buf, `%%q:`, pair.Name)")
	o.L("if pair.Name == AudienceKey {")
	// Need to handle audience flattening specially
	o.L("if aud, ok := pair.Value.(types.StringList); ok {")
	o.L("audBytes, err := json.MarshalAudience(aud, t.options.IsEnabled(%sFlattenAudience))", pkgPrefix)
	o.L("if err != nil {")
	o.L("return nil, fmt.Errorf(`failed to encode \"aud\": %%w`, err)")
	o.L("}")
	o.L("buf.Write(audBytes)")
	o.L("continue")
	o.L("}")
	o.L("}")
	o.L("valBytes, err := json.Marshal(pair.Value)")
	o.L("if err != nil {")
	o.L("return nil, fmt.Errorf(`failed to encode value for field %%q: %%w`, pair.Name, err)")
	o.L("}")
	o.L("buf.Write(valBytes)")
	o.L("}")
	o.L("buf.WriteByte('}')")
	o.L("putClaimPairList(pairs)")
	o.L("ret := make([]byte, buf.Len())")
	o.L("copy(ret, buf.Bytes())")
	o.L("return ret, nil")
	o.L("}")
}

func generateToken(obj *codegen.Object) error {
	var buf bytes.Buffer

	o := codegen.NewOutput(&buf)
	o.L("// Code generated by tools/cmd/genjwt/main.go. DO NOT EDIT.")
	o.LL("package %s", obj.String(`package`))

	o.LL(`import "encoding/json/jsontext"`)

	o.WriteImportPkgs()

	pkgPrefix := computePkgPrefix(obj)

	generateTokenConstants(o, obj)
	generateTokenInterface(o, obj, pkgPrefix)
	generateTokenStruct(o, obj, pkgPrefix)
	generateTokenConstructor(o, obj, pkgPrefix)
	generateTokenHas(o, obj)
	generateTokenFieldAndGet(o, obj)
	generateTokenRemove(o, obj)
	generateTokenSet(o, obj)
	generateTokenGetters(o, obj)
	generateTokenPrivateClaims(o, obj)
	generateTokenUnmarshalJSON(o, obj)
	generateTokenKeys(o, obj)
	generateTokenClaims(o, obj)
	generateTokenCloneFrom(o, obj)
	generateTokenMakePairsAndMarshal(o, obj, pkgPrefix)

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
	o.L("claims map[string]any")
	o.L("}")

	o.LL("func NewBuilder() *Builder {")
	o.L("return &Builder{}")
	o.L("}")

	o.LL("func (b *Builder) init() {")
	o.L("if b.claims == nil {")
	o.L("b.claims = make(map[string]any)")
	o.L("}")
	o.L("}")

	o.LL("func (b *Builder) Claim(name string, value any) *Builder {")
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
