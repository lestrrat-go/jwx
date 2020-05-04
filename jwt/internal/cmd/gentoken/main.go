package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/lestrrat-go/jwx/internal/codegen"
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
	prefix     string
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
			prefix:     "std",
			pkg:        "jwt",
			filename:   "token_gen.go",
			ifName:     "Token",
			structName: "stdToken",
			claims:     stdFields,
		},
		{
			prefix:     "openid",
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
	fmt.Fprintf(&buf, "\npackage %s", tt.pkg)

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
	fmt.Fprintf(&buf, "\nIterate(context.Context) Iterator")
	fmt.Fprintf(&buf, "\nWalk(context.Context, Visitor) error")
	fmt.Fprintf(&buf, "\nAsMap(context.Context) (map[string]interface{}, error)")
	fmt.Fprintf(&buf, "\n}")

	fmt.Fprintf(&buf, "\ntype %s struct {", tt.structName)
	for _, f := range fields {
		fmt.Fprintf(&buf, "\n%s %s // %s", f.name, fieldStorageType(f.typ), f.Comment)
	}
	fmt.Fprintf(&buf, "\nprivateClaims map[string]interface{} `json:\"-\"`")
	fmt.Fprintf(&buf, "\n}") // end type Token

	// Proxy is used when unmarshaling headers
	fmt.Fprintf(&buf, "\n\ntype %sTokenMarshalProxy struct {", tt.prefix)
	for _, f := range fields {
		fmt.Fprintf(&buf, "\nX%s %s `%s`", f.name, fieldStorageType(f.typ), f.Tag())
	}
	fmt.Fprintf(&buf, "\n}")

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
	fmt.Fprintf(&buf, "\nprivateClaims: make(map[string]interface{}),")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\n}")

	fmt.Fprintf(&buf, "\n\n// Size returns the number of valid claims stored in this token")
	fmt.Fprintf(&buf, "\nfunc (t *%s) Size() int {", tt.structName)
	fmt.Fprintf(&buf, "\nvar count int")
	for _, field := range fields {
		switch {
		case field.IsList():
			fmt.Fprintf(&buf, "\nif len(t.%s) > 0 {", field.name)
			fmt.Fprintf(&buf, "\ncount++")
			fmt.Fprintf(&buf, "\n}")
		case field.IsPointer():
			fmt.Fprintf(&buf, "\nif t.%s != nil {", field.name)
			fmt.Fprintf(&buf, "\ncount++")
			fmt.Fprintf(&buf, "\n}")
		}
	}

	fmt.Fprintf(&buf, "\ncount += len(t.privateClaims)")
	fmt.Fprintf(&buf, "\nreturn count")
	fmt.Fprintf(&buf, "\n}") // end func Size()
	fmt.Fprintf(&buf, "\n\nfunc (t *%s) Get(name string) (interface{}, bool) {", tt.structName)
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

	fmt.Fprintf(&buf, "\n\nfunc (h *%s) Set(name string, value interface{}) error {", tt.structName)
	fmt.Fprintf(&buf, "\nswitch name {")
	for _, f := range fields {
		keyName := f.method + "Key"
		fmt.Fprintf(&buf, "\ncase %s:", keyName)
		if f.name == `algorithm` {
			fmt.Fprintf(&buf, "\nswitch v := value.(type) {")
			fmt.Fprintf(&buf, "\ncase string:")
			fmt.Fprintf(&buf, "\nh.algorithm = &v")
			fmt.Fprintf(&buf, "\ncase fmt.Stringer:")
			fmt.Fprintf(&buf, "\ntmp := v.String()")
			fmt.Fprintf(&buf, "\nh.algorithm = &tmp")
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
			fmt.Fprintf(&buf, "\n}") // end if err := h.%s.Accept(value)
			if fieldStorageTypeIsIndirect(f.typ) || f.IsPointer() {
				fmt.Fprintf(&buf, "\nh.%s = &acceptor", f.name)
			} else {
				fmt.Fprintf(&buf, "\nh.%s = acceptor", f.name)
			}
			fmt.Fprintf(&buf, "\nreturn nil")
		} else {
			fmt.Fprintf(&buf, "\nif v, ok := value.(%s); ok {", f.typ)
			if fieldStorageTypeIsIndirect(f.typ) {
				fmt.Fprintf(&buf, "\nh.%s = &v", f.name)
			} else {
				fmt.Fprintf(&buf, "\nh.%s = v", f.name)
			}
			fmt.Fprintf(&buf, "\nreturn nil")
			fmt.Fprintf(&buf, "\n}") // end if v, ok := value.(%s)
			fmt.Fprintf(&buf, "\nreturn errors.Errorf(`invalid value for %%s key: %%T`, %s, value)", keyName)
		}
	}
	fmt.Fprintf(&buf, "\ndefault:")
	fmt.Fprintf(&buf, "\nif h.privateClaims == nil {")
	fmt.Fprintf(&buf, "\nh.privateClaims = map[string]interface{}{}")
	fmt.Fprintf(&buf, "\n}") // end if h.privateClaims == nil
	fmt.Fprintf(&buf, "\nh.privateClaims[name] = value")
	fmt.Fprintf(&buf, "\n}") // end switch name
	fmt.Fprintf(&buf, "\nreturn nil")
	fmt.Fprintf(&buf, "\n}") // end func (h *%s) Set(name string, value interface{})

	for _, f := range fields {
		fmt.Fprintf(&buf, "\n\nfunc (h *%s) %s() ", tt.structName, f.method)
		if f.returnType != "" {
			fmt.Fprintf(&buf, "%s", f.returnType)
		} else if f.IsPointer() && f.noDeref {
			fmt.Fprintf(&buf, "%s", f.typ)
		} else {
			fmt.Fprintf(&buf, "%s", f.PointerElem())
		}
		fmt.Fprintf(&buf, " {")

		if f.hasGet {
			fmt.Fprintf(&buf, "\nif h.%s != nil {", f.name)
			fmt.Fprintf(&buf, "\nreturn h.%s.Get()", f.name)
			fmt.Fprintf(&buf, "\n}")
			fmt.Fprintf(&buf, "\nreturn %s", zeroval(f.returnType))
		} else if !f.IsPointer() {
			if fieldStorageTypeIsIndirect(f.typ) {
				fmt.Fprintf(&buf, "\nif h.%s != nil {", f.name)
				fmt.Fprintf(&buf, "\nreturn *(h.%s)", f.name)
				fmt.Fprintf(&buf, "\n}")
				fmt.Fprintf(&buf, "\nreturn %s", zeroval(f.returnType))
			} else {
				fmt.Fprintf(&buf, "\nreturn h.%s", f.name)
			}
		} else {
			fmt.Fprintf(&buf, "\nreturn h.%s", f.name)
		}
		fmt.Fprintf(&buf, "\n}") // func (h *stdHeaders) %s() %s
	}

	fmt.Fprintf(&buf, "\n\nfunc (t *%s) PrivateClaims() map[string]interface{} {", tt.structName)
	fmt.Fprintf(&buf, "\nreturn t.privateClaims")
	fmt.Fprintf(&buf, "\n}")

	// Generate a function that iterates through all of the keys
	// in this header.
	fmt.Fprintf(&buf, "\n\nfunc (h *%s) iterate(ctx context.Context, ch chan *ClaimPair) {", tt.structName)
	fmt.Fprintf(&buf, "\ndefer close(ch)")

	// NOTE: building up an array is *slow*?
	fmt.Fprintf(&buf, "\n\nvar pairs []*ClaimPair")
	for _, f := range fields {
		keyName := f.method + "Key"
		fmt.Fprintf(&buf, "\nif h.%s != nil {", f.name)
		if f.hasGet {
			fmt.Fprintf(&buf, "\nv := h.%s.Get()", f.name)
		} else {
			if fieldStorageTypeIsIndirect(f.typ) {
				fmt.Fprintf(&buf, "\nv := *(h.%s)", f.name)
			} else {
				fmt.Fprintf(&buf, "\nv := h.%s", f.name)
			}
		}
		fmt.Fprintf(&buf, "\npairs = append(pairs, &ClaimPair{Key: %s, Value: v})", keyName)
		fmt.Fprintf(&buf, "\n}")
	}
	fmt.Fprintf(&buf, "\nfor k, v := range h.privateClaims {")
	fmt.Fprintf(&buf, "\npairs = append(pairs, &ClaimPair{Key: k, Value: v})")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\nfor _, pair := range pairs {")
	fmt.Fprintf(&buf, "\nselect {")
	fmt.Fprintf(&buf, "\ncase <-ctx.Done():")
	fmt.Fprintf(&buf, "\nreturn")
	fmt.Fprintf(&buf, "\ncase ch<-pair:")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\n}") // end of (h *stdHeaders) iterate(...)
	/*


			switch {
			case field.IsList():
				fmt.Fprintf(&buf, "\n\nfunc (t *%s) %s() %s {", tt.structName, field.method, field.typ)
				fmt.Fprintf(&buf, "\nif v, ok := t.Get(%sKey); ok {", field.method)
				fmt.Fprintf(&buf, "\nreturn v.([]string)")
				fmt.Fprintf(&buf, "\n}") // end if v, ok := t.Get(%sKey)
				fmt.Fprintf(&buf, "\nreturn nil")
				fmt.Fprintf(&buf, "\n}") // end func (t stdToken) %s() %s
			case field.typ == "*types.NumericDate":
				fmt.Fprintf(&buf, "\n\nfunc (t *%s) %s() time.Time {", tt.structName, field.method)
				fmt.Fprintf(&buf, "\nif v, ok := t.Get(%sKey); ok {", field.method)
				fmt.Fprintf(&buf, "\nreturn v.(time.Time)")
				fmt.Fprintf(&buf, "\n}")
				fmt.Fprintf(&buf, "\nreturn time.Time{}")
				fmt.Fprintf(&buf, "\n}") // end func (t Token) %s()
			case field.IsPointer():
				fmt.Fprintf(&buf, "\n\n// %s is a convenience function to retrieve the corresponding value store in the token", field.method)
				fmt.Fprintf(&buf, "\n// if there is a problem retrieving the value, the zero value is returned. If you need to differentiate between existing/non-existing values, use `Get` instead")
				fmt.Fprintf(&buf, "\n\nfunc (t *%s) %s() %s {", tt.structName, field.method, field.PointerElem())
				fmt.Fprintf(&buf, "\nif v, ok := t.Get(%sKey); ok {", field.method)
				fmt.Fprintf(&buf, "\nreturn v.(%s)", field.PointerElem())
				fmt.Fprintf(&buf, "\n}") // end if v, ok := t.Get(%sKey)
				fmt.Fprintf(&buf, "\nreturn %s", zeroval(field.PointerElem()))
				fmt.Fprintf(&buf, "\n}") // end func (t Token) %s() %s
			}
		}
	*/

	// JSON related stuff
	fmt.Fprintf(&buf, "\n\n// this is almost identical to json.Encoder.Encode(), but we use Marshal")
	fmt.Fprintf(&buf, "\n// to avoid having to remove the trailing newline for each successive")
	fmt.Fprintf(&buf, "\n// call to Encode()")
	fmt.Fprintf(&buf, "\nfunc writeJSON(buf *bytes.Buffer, v interface{}, keyName string) error {")
	fmt.Fprintf(&buf, "\nif enc, err := json.Marshal(v); err != nil {")
	fmt.Fprintf(&buf, "\nreturn errors.Wrapf(err, `failed to encode '%%s'`, keyName)")
	fmt.Fprintf(&buf, "\n} else {")
	fmt.Fprintf(&buf, "\nbuf.Write(enc)")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\nreturn nil")
	fmt.Fprintf(&buf, "\n}")

	fmt.Fprintf(&buf, "\n\nfunc (h *%s) UnmarshalJSON(buf []byte) error {", tt.structName)
	fmt.Fprintf(&buf, "\nvar proxy %sTokenMarshalProxy", tt.prefix)
	fmt.Fprintf(&buf, "\nif err := json.Unmarshal(buf, &proxy); err != nil {")
	fmt.Fprintf(&buf, "\nreturn errors.Wrap(err, `failed to unmarshal %s`)", tt.structName)
	fmt.Fprintf(&buf, "\n}")

	for _, f := range fields {
		switch f.typ {
		case byteSliceType:
			// XXX encoding/json uses base64.StdEncoding, which require padding
			// but we may or may not be dealing with padded base64's.
			// The unmarshal proxy takes this into account, and grabs the value
			// as strings so that we can do our own decoding magic
			fmt.Fprintf(&buf, "\nif h.%[1]s = nil; proxy.X%[1]s != nil {", f.name)
			fmt.Fprintf(&buf, "\ndecoded, err := base64.DecodeString(*(proxy.X%[1]s))", f.name)
			fmt.Fprintf(&buf, "\nif err != nil {")
			fmt.Fprintf(&buf, "\nreturn errors.Wrap(err, `failed to decode base64 value for %s`)", f.name)
			fmt.Fprintf(&buf, "\n}")
			fmt.Fprintf(&buf, "\nh.%[1]s = decoded", f.name)
			fmt.Fprintf(&buf, "\n}")
		default:
			fmt.Fprintf(&buf, "\nh.%[1]s = proxy.X%[1]s", f.name)
		}
	}

	// Now for the fun part... It's quite silly, but we need to check if we
	// have other parameters.
	fmt.Fprintf(&buf, "\nvar m map[string]interface{}")
	fmt.Fprintf(&buf, "\nif err := json.Unmarshal(buf, &m); err != nil {")
	fmt.Fprintf(&buf, "\nreturn errors.Wrap(err, `failed to parse privsate parameters`)")
	fmt.Fprintf(&buf, "\n}")
	// Delete all known keys
	for _, f := range fields {
		keyName := f.method + "Key"
		fmt.Fprintf(&buf, "\ndelete(m, %s)", keyName)
	}

	fmt.Fprintf(&buf, "\nh.privateClaims = m")
	fmt.Fprintf(&buf, "\nreturn nil")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\n\nfunc (h %s) MarshalJSON() ([]byte, error) {", tt.structName)
	fmt.Fprintf(&buf, "\nvar proxy %sTokenMarshalProxy", tt.prefix)
	for _, f := range fields {
		switch f.typ {
		case byteSliceType:
			// XXX encoding/json uses base64.StdEncoding, which require padding
			// but we may or may not be dealing with padded base64's.
			// Before marshaling this value to JSON, we must first encode it
			fmt.Fprintf(&buf, "\nif len(h.%s) > 0 {", f.name)
			fmt.Fprintf(&buf, "\nv := base64.EncodeToString(h.%s)", f.name)
			fmt.Fprintf(&buf, "\nproxy.X%s = &v", f.name)
			fmt.Fprintf(&buf, "\n}")
		default:
			fmt.Fprintf(&buf, "\nproxy.X%[1]s = h.%[1]s", f.name)
		}
	}

	fmt.Fprintf(&buf, "\nvar buf bytes.Buffer")
	fmt.Fprintf(&buf, "\nenc := json.NewEncoder(&buf)")
	fmt.Fprintf(&buf, "\nif err := enc.Encode(proxy); err != nil {")
	fmt.Fprintf(&buf, "\nreturn nil, errors.Wrap(err, `failed to encode proxy to JSON`)")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\nhasContent := buf.Len() > 3 // encoding/json always adds a newline, so \"{}\\n\" is the empty hash")
	fmt.Fprintf(&buf, "\nif l := len(h.privateClaims); l> 0 {")
	fmt.Fprintf(&buf, "\nbuf.Truncate(buf.Len()-2)")
	fmt.Fprintf(&buf, "\nkeys := make([]string, 0, l)")
	fmt.Fprintf(&buf, "\nfor k := range h.privateClaims {")
	fmt.Fprintf(&buf, "\nkeys = append(keys, k)")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\nsort.Strings(keys)")
	fmt.Fprintf(&buf, "\nfor i, k := range keys {")
	fmt.Fprintf(&buf, "\nif hasContent || i > 0 {")
	fmt.Fprintf(&buf, "\nfmt.Fprintf(&buf, `,`)")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\nfmt.Fprintf(&buf, `%%s:`, strconv.Quote(k))")
	fmt.Fprintf(&buf, "\nif err := enc.Encode(h.privateClaims[k]); err != nil {")
	fmt.Fprintf(&buf, "\nreturn nil, errors.Wrapf(err, `failed to encode private param %%s`, k)")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\nfmt.Fprintf(&buf, `}`)")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\nreturn buf.Bytes(), nil")
	fmt.Fprintf(&buf, "\n}") // end of MarshalJSON

	fmt.Fprintf(&buf, "\n\nfunc (h *%s) Iterate(ctx context.Context) Iterator {", tt.structName)
	fmt.Fprintf(&buf, "\nch := make(chan *ClaimPair)")
	fmt.Fprintf(&buf, "\ngo h.iterate(ctx, ch)")
	fmt.Fprintf(&buf, "\nreturn mapiter.New(ch)")
	fmt.Fprintf(&buf, "\n}")

	fmt.Fprintf(&buf, "\n\nfunc (h *%s) Walk(ctx context.Context, visitor Visitor) error {", tt.structName)
	fmt.Fprintf(&buf, "\nreturn iter.WalkMap(ctx, h, visitor)")
	fmt.Fprintf(&buf, "\n}")

	fmt.Fprintf(&buf, "\n\nfunc (h *%s) AsMap(ctx context.Context) (map[string]interface{}, error) {", tt.structName)
	fmt.Fprintf(&buf, "\nreturn iter.AsMap(ctx, h)")
	fmt.Fprintf(&buf, "\n}")

	return codegen.WriteFormattedCodeToFile(tt.filename, &buf)
}
