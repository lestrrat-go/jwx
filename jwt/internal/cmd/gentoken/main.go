package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/lestrrat-go/codegen"
	"github.com/pkg/errors"
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

var tokens []tokenType

func _main() error {
	for _, t := range tokens {
		if err := generateToken(t); err != nil {
			return errors.Wrapf(err, `failed to generate token file %s`, t.filename)
		}
	}
	return nil
}

type tokenField struct {
	name       string
	method     string
	returnType string
	key        string
	typ        string
	Comment    string
	elemtyp    string
	tag        string
	isList     bool
	hasAccept  bool
	hasGet     bool
	noDeref    bool
}

func (t tokenField) Tag() string {
	if len(t.tag) > 0 {
		return t.tag
	}

	return `json:"` + t.key + `,omitempty"`
}

func (t tokenField) IsList() bool {
	return t.isList || strings.HasPrefix(t.typ, `[]`)
}

func (t tokenField) ListElem() string {
	if t.elemtyp != "" {
		return t.elemtyp
	}
	return strings.TrimPrefix(t.typ, `[]`)
}

func (t tokenField) IsPointer() bool {
	return strings.HasPrefix(t.typ, `*`)
}

func (t tokenField) PointerElem() string {
	return strings.TrimPrefix(t.typ, `*`)
}

var zerovals = map[string]string{
	`string`:    `""`,
	`time.Time`: `time.Time{}`,
	`bool`:      `false`,
}

func zeroval(s string) string {
	if v, ok := zerovals[s]; ok {
		return v
	}
	return `nil`
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

var stdFields []tokenField

type tokenType struct {
	filename   string
	structName string
	ifName     string
	pkg        string
	claims     []tokenField
}

func init() {
	stdFields = []tokenField{
		{
			name:       "audience",
			method:     "Audience",
			returnType: "[]string",
			key:        "aud",
			typ:        "types.StringList",
			Comment:    `https://tools.ietf.org/html/rfc7519#section-4.1.3`,
			isList:     true,
			hasAccept:  true,
			hasGet:     true,
			elemtyp:    `string`,
		},
		{
			name:       "expiration",
			method:     "Expiration",
			returnType: "time.Time",
			key:        "exp",
			typ:        "types.NumericDate",
			Comment:    `https://tools.ietf.org/html/rfc7519#section-4.1.4`,
			hasAccept:  true,
			hasGet:     true,
			noDeref:    true,
		},
		{
			name:       "issuedAt",
			method:     "IssuedAt",
			returnType: "time.Time",
			key:        "iat",
			typ:        "types.NumericDate",
			Comment:    `https://tools.ietf.org/html/rfc7519#section-4.1.6`,
			hasAccept:  true,
			hasGet:     true,
			noDeref:    true,
		},
		{
			name:       "issuer",
			method:     "Issuer",
			returnType: "string",
			key:        "iss",
			typ:        "string",
			Comment:    `https://tools.ietf.org/html/rfc7519#section-4.1.1`,
		},
		{
			name:       "jwtID",
			method:     "JwtID",
			returnType: "string",
			key:        "jti",
			typ:        "string",
			Comment:    `https://tools.ietf.org/html/rfc7519#section-4.1.7`,
		},
		{
			name:       "notBefore",
			method:     "NotBefore",
			returnType: "time.Time",
			key:        "nbf",
			typ:        "types.NumericDate",
			Comment:    `https://tools.ietf.org/html/rfc7519#section-4.1.5`,
			hasAccept:  true,
			hasGet:     true,
			noDeref:    true,
		},
		{
			name:       "subject",
			method:     "Subject",
			returnType: "string",
			key:        "sub",
			typ:        "string",
			Comment:    `https://tools.ietf.org/html/rfc7519#section-4.1.2`,
		},
	}

	tokens = []tokenType{
		{
			pkg:        "jwt",
			filename:   "token_gen.go",
			ifName:     "Token",
			structName: "stdToken",
			claims:     stdFields,
		},
		{
			pkg:        "openid",
			filename:   "openid/token_gen.go",
			ifName:     "Token",
			structName: "stdToken",
			claims: append(stdFields, []tokenField{
				{
					name:       "name",
					method:     "Name",
					returnType: "string",
					typ:        "string",
					key:        "name",
				},
				{
					name:       "givenName",
					method:     "GivenName",
					returnType: "string",
					typ:        "string",
					key:        "given_name",
				},
				{
					name:       "middleName",
					method:     "MiddleName",
					returnType: "string",
					typ:        "string",
					key:        "middle_name",
				},
				{
					name:       "familyName",
					method:     "FamilyName",
					returnType: "string",
					typ:        "string",
					key:        "family_name",
				},
				{
					name:       "nickname",
					method:     "Nickname",
					returnType: "string",
					typ:        "string",
					key:        "nickname",
				},
				{
					name:       "preferredUsername",
					method:     "PreferredUsername",
					returnType: "string",
					typ:        "string",
					key:        "preferred_username",
				},
				{
					name:       "profile",
					method:     "Profile",
					returnType: "string",
					typ:        "string",
					key:        "profile",
				},
				{
					name:       "picture",
					method:     "Picture",
					returnType: "string",
					typ:        "string",
					key:        "picture",
				},
				{
					name:       "website",
					method:     "Website",
					returnType: "string",
					typ:        "string",
					key:        "website",
				},
				{
					name:       "email",
					method:     "Email",
					returnType: "string",
					typ:        "string",
					key:        "email",
				},
				{
					name:       "emailVerified",
					method:     "EmailVerified",
					returnType: "bool",
					typ:        "bool",
					key:        "email_verified",
				},
				{
					name:       "gender",
					method:     "Gender",
					returnType: "string",
					typ:        "string",
					key:        "gender",
				},
				{
					name:       "birthdate",
					method:     "Birthdate",
					returnType: "*BirthdateClaim",
					typ:        "*BirthdateClaim",
					key:        "birthdate",
					hasAccept:  true,
				},
				{
					name:       "zoneinfo",
					method:     "Zoneinfo",
					returnType: "string",
					typ:        "string",
					key:        "zoneinfo",
				},
				{
					name:       "locale",
					method:     "Locale",
					returnType: "string",
					typ:        "string",
					key:        "locale",
				},
				{
					name:       "phoneNumber",
					method:     "PhoneNumber",
					returnType: "string",
					typ:        "string",
					key:        "phone_number",
				},
				{
					name:       "phoneNumberVerified",
					method:     "PhoneNumberVerified",
					returnType: "bool",
					typ:        "bool",
					key:        "phone_number_verified",
				},
				{
					name:       "address",
					method:     "Address",
					returnType: "*AddressClaim",
					typ:        "*AddressClaim",
					key:        "address",
					hasAccept:  true,
				},
				{
					name:       "updatedAt",
					method:     "UpdatedAt",
					returnType: "time.Time",
					typ:        "types.NumericDate",
					key:        "updated_at",
					hasGet:     true,
					hasAccept:  true,
				},
			}...),
		},
	}
}

func generateToken(tt tokenType) error {
	var buf bytes.Buffer

	var fields = tt.claims

	o := codegen.NewOutput(&buf)
	o.L("// This file is auto-generated by jwt/internal/cmd/gentoken/main.go. DO NOT EDIT")
	o.LL("package %s", tt.pkg)

	o.LL("const (")
	for _, f := range fields {
		o.L("%sKey = %s", f.method, strconv.Quote(f.key))
	}
	o.L(")") // end const

	if tt.pkg == "jwt" && tt.structName == "stdToken" {
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

	o.L("type %s interface {", tt.ifName)
	for _, field := range fields {
		o.L("%s() %s", field.method, field.returnType)
	}
	o.L("PrivateClaims() map[string]interface{}")
	o.L("Get(string) (interface{}, bool)")
	o.L("Set(string, interface{}) error")
	o.L("Remove(string) error")
	if tt.pkg != "jwt" {
		o.L("Clone() (jwt.Token, error)")
	} else {
		o.L("Clone() (Token, error)")
	}
	o.L("Iterate(context.Context) Iterator")
	o.L("Walk(context.Context, Visitor) error")
	o.L("AsMap(context.Context) (map[string]interface{}, error)")
	o.L("}")

	o.L("type %s struct {", tt.structName)
	o.L("mu *sync.RWMutex")
	o.L("dc DecodeCtx // per-object context for decoding")
	for _, f := range fields {
		o.L("%s %s // %s", f.name, fieldStorageType(f.typ), f.Comment)
	}
	o.L("privateClaims map[string]interface{}")
	o.L("}") // end type Token

	o.LL("// New creates a standard token, with minimal knowledge of")
	o.L("// possible claims. Standard claims include")
	for i, field := range fields {
		o.R("%s", strconv.Quote(field.key))
		switch {
		case i < len(fields)-2:
			o.R(", ")
		case i == len(fields)-2:
			o.R(" and ")
		}
	}
	o.R(".\n// Convenience accessors are provided for these standard claims")
	o.L("func New() %s {", tt.ifName)
	o.L("return &%s{", tt.structName)
	o.L("mu: &sync.RWMutex{},")
	o.L("privateClaims: make(map[string]interface{}),")
	o.L("}")
	o.L("}")

	o.LL("func (t *%s) Get(name string) (interface{}, bool) {", tt.structName)
	o.L("t.mu.RLock()")
	o.L("defer t.mu.RUnlock()")
	o.L("switch name {")
	for _, f := range fields {
		o.L("case %sKey:", f.method)
		o.L("if t.%s == nil {", f.name)
		o.L("return nil, false")
		o.L("}")
		if f.hasGet {
			o.L("v := t.%s.Get()", f.name)
		} else {
			if fieldStorageTypeIsIndirect(f.typ) {
				o.L("v := *(t.%s)", f.name)
			} else {
				o.L("v := t.%s", f.name)
			}
		}
		o.L("return v, true")
	}
	o.L("default:")
	o.L("v, ok := t.privateClaims[name]")
	o.L("return v, ok")
	o.L("}") // end switch name
	o.L("}") // end of Get

	o.LL("func (t *stdToken) Remove(key string) error {")
	o.L("t.mu.Lock()")
	o.L("defer t.mu.Unlock()")
	o.L("switch key {")
	for _, f := range fields {
		o.L("case %sKey:", f.method)
		o.L("t.%s = nil", f.name)
	}
	o.L("default:")
	o.L("delete(t.privateClaims, key)")
	o.L("}")
	o.L("return nil") // currently unused, but who knows
	o.L("}")

	o.LL("func (t *%s) Set(name string, value interface{}) error {", tt.structName)
	o.L("t.mu.Lock()")
	o.L("defer t.mu.Unlock()")
	o.L("return t.setNoLock(name, value)")
	o.L("}")

	o.LL("func (t *%s) DecodeCtx() DecodeCtx {", tt.structName)
	o.L("t.mu.RLock()")
	o.L("defer t.mu.RUnlock()")
	o.L("return t.dc")
	o.L("}")

	o.LL("func (t *%s) SetDecodeCtx(v DecodeCtx) {", tt.structName)
	o.L("t.mu.Lock()")
	o.L("defer t.mu.Unlock()")
	o.L("t.dc = v")
	o.L("}")

	o.LL("func (t *%s) setNoLock(name string, value interface{}) error {", tt.structName)
	o.L("switch name {")
	for _, f := range fields {
		keyName := f.method + "Key"
		o.L("case %s:", keyName)
		if f.name == `algorithm` {
			o.L("switch v := value.(type) {")
			o.L("case string:")
			o.L("t.algorithm = &v")
			o.L("case fmt.Stringer:")
			o.L("tmp := v.String()")
			o.L("t.algorithm = &tmp")
			o.L("default:")
			o.L("return errors.Errorf(`invalid type for %%s key: %%T`, %s, value)", keyName)
			o.L("}")
			o.L("return nil")
		} else if f.hasAccept {
			if f.IsPointer() {
				o.L("var acceptor %s", strings.TrimPrefix(f.typ, "*"))
			} else {
				o.L("var acceptor %s", f.typ)
			}

			o.L("if err := acceptor.Accept(value); err != nil {")
			o.L("return errors.Wrapf(err, `invalid value for %%s key`, %s)", keyName)
			o.L("}") // end if err := t.%s.Accept(value)
			if fieldStorageTypeIsIndirect(f.typ) || f.IsPointer() {
				o.L("t.%s = &acceptor", f.name)
			} else {
				o.L("t.%s = acceptor", f.name)
			}
			o.L("return nil")
		} else {
			o.L("if v, ok := value.(%s); ok {", f.typ)
			if fieldStorageTypeIsIndirect(f.typ) {
				o.L("t.%s = &v", f.name)
			} else {
				o.L("t.%s = v", f.name)
			}
			o.L("return nil")
			o.L("}") // end if v, ok := value.(%s)
			o.L("return errors.Errorf(`invalid value for %%s key: %%T`, %s, value)", keyName)
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
		o.LL("func (t *%s) %s() ", tt.structName, f.method)
		if f.returnType != "" {
			o.R("%s", f.returnType)
		} else if f.IsPointer() && f.noDeref {
			o.R("%s", f.typ)
		} else {
			o.R("%s", f.PointerElem())
		}
		o.R(" {")
		o.L("t.mu.RLock()")
		o.L("defer t.mu.RUnlock()")

		if f.hasGet {
			o.L("if t.%s != nil {", f.name)
			o.L("return t.%s.Get()", f.name)
			o.L("}")
			o.L("return %s", zeroval(f.returnType))
		} else if !f.IsPointer() {
			if fieldStorageTypeIsIndirect(f.typ) {
				o.L("if t.%s != nil {", f.name)
				o.L("return *(t.%s)", f.name)
				o.L("}")
				o.L("return %s", zeroval(f.returnType))
			} else {
				o.L("return t.%s", f.name)
			}
		} else {
			o.L("return t.%s", f.name)
		}
		o.L("}") // func (h *stdHeaders) %s() %s
	}

	o.LL("func (t *%s) PrivateClaims() map[string]interface{} {", tt.structName)
	o.L("t.mu.RLock()")
	o.L("defer t.mu.RUnlock()")
	o.L("return t.privateClaims")
	o.L("}")

	// Generate a function that iterates through all of the keys
	// in this header.
	o.LL("func (t *%s) makePairs() []*ClaimPair {", tt.structName)
	o.L("t.mu.RLock()")
	o.L("defer t.mu.RUnlock()")

	// NOTE: building up an array is *slow*?
	o.LL("pairs := make([]*ClaimPair, 0, %d)", len(fields))
	for _, f := range fields {
		keyName := f.method + "Key"
		o.L("if t.%s != nil {", f.name)
		if f.hasGet {
			o.L("v := t.%s.Get()", f.name)
		} else {
			if fieldStorageTypeIsIndirect(f.typ) {
				o.L("v := *(t.%s)", f.name)
			} else {
				o.L("v := t.%s", f.name)
			}
		}
		o.L("pairs = append(pairs, &ClaimPair{Key: %s, Value: v})", keyName)
		o.L("}")
	}
	o.L("for k, v := range t.privateClaims {")
	o.L("pairs = append(pairs, &ClaimPair{Key: k, Value: v})")
	o.L("}")
	o.L("sort.Slice(pairs, func(i, j int) bool {")
	o.L("return pairs[i].Key.(string) < pairs[j].Key.(string)")
	o.L("})")
	o.L("return pairs")
	o.L("}") // end of (h *stdHeaders) iterate(...)

	o.LL("func (t *stdToken) UnmarshalJSON(buf []byte) error {")
	o.L("t.mu.Lock()")
	o.L("defer t.mu.Unlock()")
	for _, f := range fields {
		o.L("t.%s = nil", f.name)
	}

	o.L("dec := json.NewDecoder(bytes.NewReader(buf))")
	o.L("LOOP:")
	o.L("for {")
	o.L("tok, err := dec.Token()")
	o.L("if err != nil {")
	o.L("return errors.Wrap(err, `error reading token`)")
	o.L("}")
	o.L("switch tok := tok.(type) {")
	o.L("case json.Delim:")
	o.L("// Assuming we're doing everything correctly, we should ONLY")
	o.L("// get either '{' or '}' here.")
	o.L("if tok == '}' { // End of object")
	o.L("break LOOP")
	o.L("} else if tok != '{' {")
	o.L("return errors.Errorf(`expected '{', but got '%%c'`, tok)")
	o.L("}")
	o.L("case string: // Objects can only have string keys")
	o.L("switch tok {")

	for _, f := range fields {
		if f.typ == "string" {
			o.L("case %sKey:", f.method)
			o.L("if err := json.AssignNextStringToken(&t.%s, dec); err != nil {", f.name)
			o.L("return errors.Wrapf(err, `failed to decode value for key %%s`, %sKey)", f.method)
			o.L("}")
		} else if f.typ == byteSliceType {
			name := f.method
			o.L("case %sKey:", name)
			o.L("if err := json.AssignNextBytesToken(&t.%s, dec); err != nil {", f.name)
			o.L("return errors.Wrapf(err, `failed to decode value for key %%s`, %sKey)", name)
			o.L("}")
		} else if f.typ == "types.StringList" || strings.HasPrefix(f.typ, "[]") {
			name := f.method
			o.L("case %sKey:", name)
			o.L("var decoded %s", f.typ)
			o.L("if err := dec.Decode(&decoded); err != nil {")
			o.L("return errors.Wrapf(err, `failed to decode value for key %%s`, %sKey)", name)
			o.L("}")
			o.L("t.%s = decoded", f.name)
		} else {
			name := f.method
			o.L("case %sKey:", name)
			if strings.HasPrefix(f.typ, "*") {
				o.L("var decoded %s", f.typ[1:])
			} else {
				o.L("var decoded %s", f.typ)
			}
			o.L("if err := dec.Decode(&decoded); err != nil {")
			o.L("return errors.Wrapf(err, `failed to decode value for key %%s`, %sKey)", name)
			o.L("}")
			o.L("t.%s = &decoded", f.name)
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
	o.L("return errors.Wrapf(err, `could not decode field %%s`, tok)")
	o.L("}")
	o.L("default:")
	o.L("return errors.Errorf(`invalid token %%T`, tok)")
	o.L("}")
	o.L("}")

	o.L("return nil")
	o.L("}")

	var numericDateFields []tokenField
	for _, field := range fields {
		if field.typ == "types.NumericDate" {
			numericDateFields = append(numericDateFields, field)
		}
	}

	o.LL("func (t %s) MarshalJSON() ([]byte, error) {", tt.structName)
	o.L("t.mu.RLock()")
	o.L("defer t.mu.RUnlock()")
	o.L("buf := pool.GetBytesBuffer()")
	o.L("defer pool.ReleaseBytesBuffer(buf)")
	o.L("buf.WriteByte('{')")
	o.L("enc := json.NewEncoder(buf)")
	o.L("for i, pair := range t.makePairs() {")
	o.L("f := pair.Key.(string)")
	o.L("if i > 0 {")
	o.L("buf.WriteByte(',')")
	o.L("}")
	o.L("buf.WriteRune('\"')")
	o.L("buf.WriteString(f)")
	o.L("buf.WriteString(`\":`)")

	// Handle cases that need specialized handling
	o.L("switch f {")
	o.L("case AudienceKey:")
	o.L("if err := json.EncodeAudience(enc, pair.Value.([]string)); err != nil {")
	o.L("return nil, errors.Wrap(err, `failed to encode \"aud\"`)")
	o.L("}")
	o.L("continue")
	if lndf := len(numericDateFields); lndf > 0 {
		o.L("case ")
		for i, ndf := range numericDateFields {
			o.R("%sKey", ndf.method)
			if i < lndf-1 {
				o.R(",")
			}
		}
		o.R(":")
		o.L("enc.Encode(pair.Value.(time.Time).Unix())")
		o.L("continue")
	}
	o.L("}")

	o.L("switch v := pair.Value.(type) {")
	o.L("case []byte:")
	o.L("buf.WriteRune('\"')")
	o.L("buf.WriteString(base64.EncodeToString(v))")
	o.L("buf.WriteRune('\"')")
	o.L("default:")
	o.L("if err := enc.Encode(v); err != nil {")
	o.L("return nil, errors.Wrapf(err, `failed to marshal field %%s`, f)")
	o.L("}")
	o.L("buf.Truncate(buf.Len()-1)")
	o.L("}")
	o.L("}")
	o.L("buf.WriteByte('}')")
	o.L("ret := make([]byte, buf.Len())")
	o.L("copy(ret, buf.Bytes())")
	o.L("return ret, nil")
	o.L("}")

	o.LL("func (t *%s) Iterate(ctx context.Context) Iterator {", tt.structName)
	o.L("pairs := t.makePairs()")
	o.L("ch := make(chan *ClaimPair, len(pairs))")
	o.L("go func(ctx context.Context, ch chan *ClaimPair, pairs []*ClaimPair) {")
	o.L("defer close(ch)")
	o.L("for _, pair := range pairs {")
	o.L("select {")
	o.L("case <-ctx.Done():")
	o.L("return")
	o.L("case ch<-pair:")
	o.L("}")
	o.L("}")
	o.L("}(ctx, ch, pairs)")
	o.L("return mapiter.New(ch)")
	o.L("}")

	o.LL("func (t *%s) Walk(ctx context.Context, visitor Visitor) error {", tt.structName)
	o.L("return iter.WalkMap(ctx, t, visitor)")
	o.L("}")

	o.LL("func (t *%s) AsMap(ctx context.Context) (map[string]interface{}, error) {", tt.structName)
	o.L("return iter.AsMap(ctx, t)")
	o.L("}")

	if err := o.WriteFile(tt.filename, codegen.WithFormatCode(true)); err != nil {
		if cfe, ok := err.(codegen.CodeFormatError); ok {
			fmt.Fprint(os.Stderr, cfe.Source())
		}
		return errors.Wrapf(err, `failed to write to %s`, tt.filename)
	}
	return nil
}
