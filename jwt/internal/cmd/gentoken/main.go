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

	fmt.Fprintf(&buf, "\n// This file is auto-generated by jwt/internal/cmd/gentoken/main.go. DO NOT EDIT")
	fmt.Fprintf(&buf, "\n\npackage %s", tt.pkg)

	fmt.Fprintf(&buf, "\n\nconst (")
	for _, f := range fields {
		fmt.Fprintf(&buf, "\n%sKey = %s", f.method, strconv.Quote(f.key))
	}
	fmt.Fprintf(&buf, "\n)") // end const

	if tt.pkg == "jwt" && tt.structName == "stdToken" {
		fmt.Fprintf(&buf, "\n\n// Token represents a generic JWT token.")
		fmt.Fprintf(&buf, "\n// which are type-aware (to an extent). Other claims may be accessed via the `Get`/`Set`")
		fmt.Fprintf(&buf, "\n// methods but their types are not taken into consideration at all. If you have non-standard")
		fmt.Fprintf(&buf, "\n// claims that you must frequently access, consider creating accessors functions")
		fmt.Fprintf(&buf, "\n// like the following")
		fmt.Fprintf(&buf, "\n//\n// func SetFoo(tok jwt.Token) error")
		fmt.Fprintf(&buf, "\n// func GetFoo(tok jwt.Token) (*Customtyp, error)")
		fmt.Fprintf(&buf, "\n//\n// Embedding jwt.Token into another struct is not recommended, becase")
		fmt.Fprintf(&buf, "\n// jwt.Token needs to handle private claims, and this really does not")
		fmt.Fprintf(&buf, "\n// work well when it is embedded in other structure")
	}

	fmt.Fprintf(&buf, "\ntype %s interface {", tt.ifName)
	for _, field := range fields {
		fmt.Fprintf(&buf, "\n%s() %s", field.method, field.returnType)
	}
	fmt.Fprintf(&buf, "\nPrivateClaims() map[string]interface{}")
	fmt.Fprintf(&buf, "\nGet(string) (interface{}, bool)")
	fmt.Fprintf(&buf, "\nSet(string, interface{}) error")
	fmt.Fprintf(&buf, "\nRemove(string) error")
	if tt.pkg != "jwt" {
		fmt.Fprintf(&buf, "\nClone() (jwt.Token, error)")
	} else {
		fmt.Fprintf(&buf, "\nClone() (Token, error)")
	}
	fmt.Fprintf(&buf, "\nIterate(context.Context) Iterator")
	fmt.Fprintf(&buf, "\nWalk(context.Context, Visitor) error")
	fmt.Fprintf(&buf, "\nAsMap(context.Context) (map[string]interface{}, error)")
	fmt.Fprintf(&buf, "\n}")

	fmt.Fprintf(&buf, "\ntype decodeCtx struct {")
	fmt.Fprintf(&buf, "\nregistry *json.Registry")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\n\nfunc(c *decodeCtx) Registry() *json.Registry {")
	fmt.Fprintf(&buf, "\nreturn c.registry")
	fmt.Fprintf(&buf, "\n}")

	fmt.Fprintf(&buf, "\ntype %s struct {", tt.structName)
	fmt.Fprintf(&buf, "\nmu *sync.RWMutex")
	fmt.Fprintf(&buf, "\ndc DecodeCtx // per-object context for decoding")
	for _, f := range fields {
		fmt.Fprintf(&buf, "\n%s %s // %s", f.name, fieldStorageType(f.typ), f.Comment)
	}
	fmt.Fprintf(&buf, "\nprivateClaims map[string]interface{}")
	fmt.Fprintf(&buf, "\n}") // end type Token

	fmt.Fprintf(&buf, "\n\n// New creates a standard token, with minimal knowledge of")
	fmt.Fprintf(&buf, "\n// possible claims. Standard claims include")
	for i, field := range fields {
		fmt.Fprintf(&buf, "%s", strconv.Quote(field.key))
		switch {
		case i < len(fields)-2:
			fmt.Fprintf(&buf, ", ")
		case i == len(fields)-2:
			fmt.Fprintf(&buf, " and ")
		}
	}
	fmt.Fprintf(&buf, ".\n// Convenience accessors are provided for these standard claims")
	fmt.Fprintf(&buf, "\nfunc New() %s {", tt.ifName)
	fmt.Fprintf(&buf, "\nreturn &%s{", tt.structName)
	fmt.Fprintf(&buf, "\nmu: &sync.RWMutex{},")
	fmt.Fprintf(&buf, "\nprivateClaims: make(map[string]interface{}),")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\n}")

	fmt.Fprintf(&buf, "\n\nfunc (t *%s) Get(name string) (interface{}, bool) {", tt.structName)
	fmt.Fprintf(&buf, "\nt.mu.RLock()")
	fmt.Fprintf(&buf, "\ndefer t.mu.RUnlock()")
	fmt.Fprintf(&buf, "\nswitch name {")
	for _, f := range fields {
		fmt.Fprintf(&buf, "\ncase %sKey:", f.method)
		fmt.Fprintf(&buf, "\nif t.%s == nil {", f.name)
		fmt.Fprintf(&buf, "\nreturn nil, false")
		fmt.Fprintf(&buf, "\n}")
		if f.hasGet {
			fmt.Fprintf(&buf, "\nv := t.%s.Get()", f.name)
		} else {
			if fieldStorageTypeIsIndirect(f.typ) {
				fmt.Fprintf(&buf, "\nv := *(t.%s)", f.name)
			} else {
				fmt.Fprintf(&buf, "\nv := t.%s", f.name)
			}
		}
		fmt.Fprintf(&buf, "\nreturn v, true")
	}
	fmt.Fprintf(&buf, "\ndefault:")
	fmt.Fprintf(&buf, "\nv, ok := t.privateClaims[name]")
	fmt.Fprintf(&buf, "\nreturn v, ok")
	fmt.Fprintf(&buf, "\n}") // end switch name
	fmt.Fprintf(&buf, "\n}") // end of Get

	fmt.Fprintf(&buf, "\n\nfunc (t *stdToken) Remove(key string) error {")
	fmt.Fprintf(&buf, "\nt.mu.Lock()")
	fmt.Fprintf(&buf, "\ndefer t.mu.Unlock()")
	fmt.Fprintf(&buf, "\nswitch key {")
	for _, f := range fields {
		fmt.Fprintf(&buf, "\ncase %sKey:", f.method)
		fmt.Fprintf(&buf, "\nt.%s = nil", f.name)
	}
	fmt.Fprintf(&buf, "\ndefault:")
	fmt.Fprintf(&buf, "\ndelete(t.privateClaims, key)")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\nreturn nil") // currently unused, but who knows
	fmt.Fprintf(&buf, "\n}")

	fmt.Fprintf(&buf, "\n\nfunc (t *%s) Set(name string, value interface{}) error {", tt.structName)
	fmt.Fprintf(&buf, "\nt.mu.Lock()")
	fmt.Fprintf(&buf, "\ndefer t.mu.Unlock()")
	fmt.Fprintf(&buf, "\nreturn t.setNoLock(name, value)")
	fmt.Fprintf(&buf, "\n}")

	fmt.Fprintf(&buf, "\n\nfunc (t *%s) DecodeCtx() DecodeCtx {", tt.structName)
	fmt.Fprintf(&buf, "\nt.mu.RLock()")
	fmt.Fprintf(&buf, "\ndefer t.mu.RUnlock()")
	fmt.Fprintf(&buf, "\nreturn t.dc")
	fmt.Fprintf(&buf, "\n}")

	fmt.Fprintf(&buf, "\n\nfunc (t *%s) SetDecodeCtx(v DecodeCtx) {", tt.structName)
	fmt.Fprintf(&buf, "\nt.mu.Lock()")
	fmt.Fprintf(&buf, "\ndefer t.mu.Unlock()")
	fmt.Fprintf(&buf, "\nt.dc = v")
	fmt.Fprintf(&buf, "\n}")

	fmt.Fprintf(&buf, "\n\nfunc (t *%s) setNoLock(name string, value interface{}) error {", tt.structName)
	fmt.Fprintf(&buf, "\nswitch name {")
	for _, f := range fields {
		keyName := f.method + "Key"
		fmt.Fprintf(&buf, "\ncase %s:", keyName)
		if f.name == `algorithm` {
			fmt.Fprintf(&buf, "\nswitch v := value.(type) {")
			fmt.Fprintf(&buf, "\ncase string:")
			fmt.Fprintf(&buf, "\nt.algorithm = &v")
			fmt.Fprintf(&buf, "\ncase fmt.Stringer:")
			fmt.Fprintf(&buf, "\ntmp := v.String()")
			fmt.Fprintf(&buf, "\nt.algorithm = &tmp")
			fmt.Fprintf(&buf, "\ndefault:")
			fmt.Fprintf(&buf, "\nreturn errors.Errorf(`invalid type for %%s key: %%T`, %s, value)", keyName)
			fmt.Fprintf(&buf, "\n}")
			fmt.Fprintf(&buf, "\nreturn nil")
		} else if f.hasAccept {
			if f.IsPointer() {
				fmt.Fprintf(&buf, "\nvar acceptor %s", strings.TrimPrefix(f.typ, "*"))
			} else {
				fmt.Fprintf(&buf, "\nvar acceptor %s", f.typ)
			}

			fmt.Fprintf(&buf, "\nif err := acceptor.Accept(value); err != nil {")
			fmt.Fprintf(&buf, "\nreturn errors.Wrapf(err, `invalid value for %%s key`, %s)", keyName)
			fmt.Fprintf(&buf, "\n}") // end if err := t.%s.Accept(value)
			if fieldStorageTypeIsIndirect(f.typ) || f.IsPointer() {
				fmt.Fprintf(&buf, "\nt.%s = &acceptor", f.name)
			} else {
				fmt.Fprintf(&buf, "\nt.%s = acceptor", f.name)
			}
			fmt.Fprintf(&buf, "\nreturn nil")
		} else {
			fmt.Fprintf(&buf, "\nif v, ok := value.(%s); ok {", f.typ)
			if fieldStorageTypeIsIndirect(f.typ) {
				fmt.Fprintf(&buf, "\nt.%s = &v", f.name)
			} else {
				fmt.Fprintf(&buf, "\nt.%s = v", f.name)
			}
			fmt.Fprintf(&buf, "\nreturn nil")
			fmt.Fprintf(&buf, "\n}") // end if v, ok := value.(%s)
			fmt.Fprintf(&buf, "\nreturn errors.Errorf(`invalid value for %%s key: %%T`, %s, value)", keyName)
		}
	}
	fmt.Fprintf(&buf, "\ndefault:")
	fmt.Fprintf(&buf, "\nif t.privateClaims == nil {")
	fmt.Fprintf(&buf, "\nt.privateClaims = map[string]interface{}{}")
	fmt.Fprintf(&buf, "\n}") // end if t.privateClaims == nil
	fmt.Fprintf(&buf, "\nt.privateClaims[name] = value")
	fmt.Fprintf(&buf, "\n}") // end switch name
	fmt.Fprintf(&buf, "\nreturn nil")
	fmt.Fprintf(&buf, "\n}") // end func (t *%s) Set(name string, value interface{})

	for _, f := range fields {
		fmt.Fprintf(&buf, "\n\nfunc (t *%s) %s() ", tt.structName, f.method)
		if f.returnType != "" {
			fmt.Fprintf(&buf, "%s", f.returnType)
		} else if f.IsPointer() && f.noDeref {
			fmt.Fprintf(&buf, "%s", f.typ)
		} else {
			fmt.Fprintf(&buf, "%s", f.PointerElem())
		}
		fmt.Fprintf(&buf, " {")
		fmt.Fprintf(&buf, "\nt.mu.RLock()")
		fmt.Fprintf(&buf, "\ndefer t.mu.RUnlock()")

		if f.hasGet {
			fmt.Fprintf(&buf, "\nif t.%s != nil {", f.name)
			fmt.Fprintf(&buf, "\nreturn t.%s.Get()", f.name)
			fmt.Fprintf(&buf, "\n}")
			fmt.Fprintf(&buf, "\nreturn %s", zeroval(f.returnType))
		} else if !f.IsPointer() {
			if fieldStorageTypeIsIndirect(f.typ) {
				fmt.Fprintf(&buf, "\nif t.%s != nil {", f.name)
				fmt.Fprintf(&buf, "\nreturn *(t.%s)", f.name)
				fmt.Fprintf(&buf, "\n}")
				fmt.Fprintf(&buf, "\nreturn %s", zeroval(f.returnType))
			} else {
				fmt.Fprintf(&buf, "\nreturn t.%s", f.name)
			}
		} else {
			fmt.Fprintf(&buf, "\nreturn t.%s", f.name)
		}
		fmt.Fprintf(&buf, "\n}") // func (h *stdHeaders) %s() %s
	}

	fmt.Fprintf(&buf, "\n\nfunc (t *%s) PrivateClaims() map[string]interface{} {", tt.structName)
	fmt.Fprintf(&buf, "\nt.mu.RLock()")
	fmt.Fprintf(&buf, "\ndefer t.mu.RUnlock()")
	fmt.Fprintf(&buf, "\nreturn t.privateClaims")
	fmt.Fprintf(&buf, "\n}")

	// Generate a function that iterates through all of the keys
	// in this header.
	fmt.Fprintf(&buf, "\n\nfunc (t *%s) makePairs() []*ClaimPair {", tt.structName)
	fmt.Fprintf(&buf, "\nt.mu.RLock()")
	fmt.Fprintf(&buf, "\ndefer t.mu.RUnlock()")

	// NOTE: building up an array is *slow*?
	fmt.Fprintf(&buf, "\n\nvar pairs []*ClaimPair")
	for _, f := range fields {
		keyName := f.method + "Key"
		fmt.Fprintf(&buf, "\nif t.%s != nil {", f.name)
		if f.hasGet {
			fmt.Fprintf(&buf, "\nv := t.%s.Get()", f.name)
		} else {
			if fieldStorageTypeIsIndirect(f.typ) {
				fmt.Fprintf(&buf, "\nv := *(t.%s)", f.name)
			} else {
				fmt.Fprintf(&buf, "\nv := t.%s", f.name)
			}
		}
		fmt.Fprintf(&buf, "\npairs = append(pairs, &ClaimPair{Key: %s, Value: v})", keyName)
		fmt.Fprintf(&buf, "\n}")
	}
	fmt.Fprintf(&buf, "\nfor k, v := range t.privateClaims {")
	fmt.Fprintf(&buf, "\npairs = append(pairs, &ClaimPair{Key: k, Value: v})")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\nreturn pairs")
	fmt.Fprintf(&buf, "\n}") // end of (h *stdHeaders) iterate(...)

	fmt.Fprintf(&buf, "\n\nfunc (t *stdToken) UnmarshalJSON(buf []byte) error {")
	fmt.Fprintf(&buf, "\nt.mu.Lock()")
	fmt.Fprintf(&buf, "\ndefer t.mu.Unlock()")
	for _, f := range fields {
		fmt.Fprintf(&buf, "\nt.%s = nil", f.name)
	}

	fmt.Fprintf(&buf, "\ndec := json.NewDecoder(bytes.NewReader(buf))")
	fmt.Fprintf(&buf, "\nLOOP:")
	fmt.Fprintf(&buf, "\nfor {")
	fmt.Fprintf(&buf, "\ntok, err := dec.Token()")
	fmt.Fprintf(&buf, "\nif err != nil {")
	fmt.Fprintf(&buf, "\nreturn errors.Wrap(err, `error reading token`)")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\nswitch tok := tok.(type) {")
	fmt.Fprintf(&buf, "\ncase json.Delim:")
	fmt.Fprintf(&buf, "\n// Assuming we're doing everything correctly, we should ONLY")
	fmt.Fprintf(&buf, "\n// get either '{' or '}' here.")
	fmt.Fprintf(&buf, "\nif tok == '}' { // End of object")
	fmt.Fprintf(&buf, "\nbreak LOOP")
	fmt.Fprintf(&buf, "\n} else if tok != '{' {")
	fmt.Fprintf(&buf, "\nreturn errors.Errorf(`expected '{', but got '%%c'`, tok)")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\ncase string: // Objects can only have string keys")
	fmt.Fprintf(&buf, "\nswitch tok {")

	for _, f := range fields {
		if f.typ == "string" {
			fmt.Fprintf(&buf, "\ncase %sKey:", f.method)
			fmt.Fprintf(&buf, "\nif err := json.AssignNextStringToken(&t.%s, dec); err != nil {", f.name)
			fmt.Fprintf(&buf, "\nreturn errors.Wrapf(err, `failed to decode value for key %%s`, %sKey)", f.method)
			fmt.Fprintf(&buf, "\n}")
		} else if f.typ == byteSliceType {
			name := f.method
			fmt.Fprintf(&buf, "\ncase %sKey:", name)
			fmt.Fprintf(&buf, "\nif err := json.AssignNextBytesToken(&t.%s, dec); err != nil {", f.name)
			fmt.Fprintf(&buf, "\nreturn errors.Wrapf(err, `failed to decode value for key %%s`, %sKey)", name)
			fmt.Fprintf(&buf, "\n}")
		} else if f.typ == "types.StringList" || strings.HasPrefix(f.typ, "[]") {
			name := f.method
			fmt.Fprintf(&buf, "\ncase %sKey:", name)
			fmt.Fprintf(&buf, "\nvar decoded %s", f.typ)
			fmt.Fprintf(&buf, "\nif err := dec.Decode(&decoded); err != nil {")
			fmt.Fprintf(&buf, "\nreturn errors.Wrapf(err, `failed to decode value for key %%s`, %sKey)", name)
			fmt.Fprintf(&buf, "\n}")
			fmt.Fprintf(&buf, "\nt.%s = decoded", f.name)
		} else {
			name := f.method
			fmt.Fprintf(&buf, "\ncase %sKey:", name)
			if strings.HasPrefix(f.typ, "*") {
				fmt.Fprintf(&buf, "\nvar decoded %s", f.typ[1:])
			} else {
				fmt.Fprintf(&buf, "\nvar decoded %s", f.typ)
			}
			fmt.Fprintf(&buf, "\nif err := dec.Decode(&decoded); err != nil {")
			fmt.Fprintf(&buf, "\nreturn errors.Wrapf(err, `failed to decode value for key %%s`, %sKey)", name)
			fmt.Fprintf(&buf, "\n}")
			fmt.Fprintf(&buf, "\nt.%s = &decoded", f.name)
		}
	}
	fmt.Fprintf(&buf, "\ndefault:")
	// This looks like bad code, but we're unrolling things for maximum
	// runtime efficiency
	fmt.Fprintf(&buf, "\nif dc := t.dc; dc != nil {")
	fmt.Fprintf(&buf, "\nif localReg := dc.Registry(); localReg != nil {")
	fmt.Fprintf(&buf, "\ndecoded, err := localReg.Decode(dec, tok)")
	fmt.Fprintf(&buf, "\nif err == nil {")
	fmt.Fprintf(&buf, "\nt.setNoLock(tok, decoded)")
	fmt.Fprintf(&buf, "\ncontinue")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\n}")

	fmt.Fprintf(&buf, "\ndecoded, err := registry.Decode(dec, tok)")
	fmt.Fprintf(&buf, "\nif err == nil {")
	fmt.Fprintf(&buf, "\nt.setNoLock(tok, decoded)")
	fmt.Fprintf(&buf, "\ncontinue")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\nreturn errors.Wrapf(err, `could not decode field %%s`, tok)")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\ndefault:")
	fmt.Fprintf(&buf, "\nreturn errors.Errorf(`invalid token %%T`, tok)")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\n}")

	fmt.Fprintf(&buf, "\nreturn nil")
	fmt.Fprintf(&buf, "\n}")

	var numericDateFields []tokenField
	for _, field := range fields {
		if field.typ == "types.NumericDate" {
			numericDateFields = append(numericDateFields, field)
		}
	}

	fmt.Fprintf(&buf, "\n\nfunc (t %s) MarshalJSON() ([]byte, error) {", tt.structName)
	fmt.Fprintf(&buf, "\nt.mu.RLock()")
	fmt.Fprintf(&buf, "\ndefer t.mu.RUnlock()")
	fmt.Fprintf(&buf, "\nctx, cancel := context.WithCancel(context.Background())")
	fmt.Fprintf(&buf, "\ndefer cancel()")
	fmt.Fprintf(&buf, "\ndata := make(map[string]interface{})")
	fmt.Fprintf(&buf, "\nfields := make([]string, 0, %d)", len(fields))
	fmt.Fprintf(&buf, "\nfor iter := t.Iterate(ctx); iter.Next(ctx); {")
	fmt.Fprintf(&buf, "\npair := iter.Pair()")
	fmt.Fprintf(&buf, "\nfields = append(fields, pair.Key.(string))")
	fmt.Fprintf(&buf, "\ndata[pair.Key.(string)] = pair.Value")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\n\nsort.Strings(fields)")
	fmt.Fprintf(&buf, "\nbuf := pool.GetBytesBuffer()")
	fmt.Fprintf(&buf, "\ndefer pool.ReleaseBytesBuffer(buf)")
	fmt.Fprintf(&buf, "\nbuf.WriteByte('{')")
	fmt.Fprintf(&buf, "\nenc := json.NewEncoder(buf)")
	fmt.Fprintf(&buf, "\nfor i, f := range fields {")
	fmt.Fprintf(&buf, "\nif i > 0 {")
	fmt.Fprintf(&buf, "\nbuf.WriteByte(',')")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\nbuf.WriteRune('\"')")
	fmt.Fprintf(&buf, "\nbuf.WriteString(f)")
	fmt.Fprintf(&buf, "\nbuf.WriteString(`\":`)")

	// Handle cases that need specialized handling
	fmt.Fprintf(&buf, "\nswitch f {")
	fmt.Fprintf(&buf, "\ncase AudienceKey:")
	fmt.Fprintf(&buf, "\nif err := json.EncodeAudience(enc, data[f].([]string)); err != nil {")
	fmt.Fprintf(&buf, "\nreturn nil, errors.Wrap(err, `failed to encode \"aud\"`)")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\ncontinue")
	if lndf := len(numericDateFields); lndf > 0 {
		fmt.Fprintf(&buf, "\ncase ")
		for i, ndf := range numericDateFields {
			fmt.Fprintf(&buf, "%sKey", ndf.method)
			if i < lndf-1 {
				fmt.Fprintf(&buf, ",")
			}
		}
		fmt.Fprintf(&buf, ":")
		fmt.Fprintf(&buf, "\nenc.Encode(data[f].(time.Time).Unix())")
		fmt.Fprintf(&buf, "\ncontinue")
	}
	fmt.Fprintf(&buf, "\n}")

	fmt.Fprintf(&buf, "\nv := data[f]")
	fmt.Fprintf(&buf, "\nswitch v := v.(type) {")
	fmt.Fprintf(&buf, "\ncase []byte:")
	fmt.Fprintf(&buf, "\nbuf.WriteRune('\"')")
	fmt.Fprintf(&buf, "\nbuf.WriteString(base64.EncodeToString(v))")
	fmt.Fprintf(&buf, "\nbuf.WriteRune('\"')")
	fmt.Fprintf(&buf, "\ndefault:")
	fmt.Fprintf(&buf, "\nif err := enc.Encode(v); err != nil {")
	fmt.Fprintf(&buf, "\nreturn nil, errors.Wrapf(err, `failed to marshal field %%s`, f)")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\nbuf.Truncate(buf.Len()-1)")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\nbuf.WriteByte('}')")
	fmt.Fprintf(&buf, "\nret := make([]byte, buf.Len())")
	fmt.Fprintf(&buf, "\ncopy(ret, buf.Bytes())")
	fmt.Fprintf(&buf, "\nreturn ret, nil")
	fmt.Fprintf(&buf, "\n}")

	fmt.Fprintf(&buf, "\n\nfunc (t *%s) Iterate(ctx context.Context) Iterator {", tt.structName)
	fmt.Fprintf(&buf, "\npairs := t.makePairs()")
	fmt.Fprintf(&buf, "\nch := make(chan *ClaimPair, len(pairs))")
	fmt.Fprintf(&buf, "\ngo func(ctx context.Context, ch chan *ClaimPair, pairs []*ClaimPair) {")
	fmt.Fprintf(&buf, "\ndefer close(ch)")
	fmt.Fprintf(&buf, "\nfor _, pair := range pairs {")
	fmt.Fprintf(&buf, "\nselect {")
	fmt.Fprintf(&buf, "\ncase <-ctx.Done():")
	fmt.Fprintf(&buf, "\nreturn")
	fmt.Fprintf(&buf, "\ncase ch<-pair:")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\n}(ctx, ch, pairs)")
	fmt.Fprintf(&buf, "\nreturn mapiter.New(ch)")
	fmt.Fprintf(&buf, "\n}")

	fmt.Fprintf(&buf, "\n\nfunc (t *%s) Walk(ctx context.Context, visitor Visitor) error {", tt.structName)
	fmt.Fprintf(&buf, "\nreturn iter.WalkMap(ctx, t, visitor)")
	fmt.Fprintf(&buf, "\n}")

	fmt.Fprintf(&buf, "\n\nfunc (t *%s) AsMap(ctx context.Context) (map[string]interface{}, error) {", tt.structName)
	fmt.Fprintf(&buf, "\nreturn iter.AsMap(ctx, t)")
	fmt.Fprintf(&buf, "\n}")

	if err := codegen.WriteFile(tt.filename, &buf, codegen.WithFormatCode(true)); err != nil {
		if cfe, ok := err.(codegen.CodeFormatError); ok {
			fmt.Fprint(os.Stderr, cfe.Source())
		}
		return errors.Wrapf(err, `failed to write to %s`, tt.filename)
	}
	return nil
}
