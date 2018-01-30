package main

import (
	"bytes"
	"fmt"
	"go/format"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

func main() {
	if err := _main(); err != nil {
		log.Printf("%s", err)
		os.Exit(1)
	}
}

func _main() error {
	if err := generateToken(); err != nil {
		return errors.Wrap(err, `failed to generate token file`)
	}
	return nil
}

type tokenField struct {
	Name      string
	JSONKey   string
	Type      string
	Comment   string
	isList    bool
	hasAccept bool
	noDeref   bool
	elemType  string
}

func (t tokenField) UpperName() string {
	return strings.Title(t.Name)
}

func (t tokenField) IsList() bool {
	return t.isList || strings.HasPrefix(t.Type, `[]`)
}

func (t tokenField) ListElem() string {
	if t.elemType != "" {
		return t.elemType
	}
	return strings.TrimPrefix(t.Type, `[]`)
}

func (t tokenField) IsPointer() bool {
	return strings.HasPrefix(t.Type, `*`)
}

func (t tokenField) PointerElem() string {
	return strings.TrimPrefix(t.Type, `*`)
}

var zerovals = map[string]string{
	`string`: `""`,
}

func zeroval(s string) string {
	if v, ok := zerovals[s]; ok {
		return v
	}
	return `nil`
}

func generateToken() error {
	var buf bytes.Buffer

	var fields = []tokenField{
		{
			Name:      "audience",
			JSONKey:   "aud",
			Type:      "stringList",
			Comment:   `https://tools.ietf.org/html/rfc7519#section-4.1.3`,
			isList:    true,
			hasAccept: true,
			elemType:  `string`,
		},
		{
			Name:      "expiration",
			JSONKey:   "exp",
			Type:      "*NumericDate",
			Comment:   `https://tools.ietf.org/html/rfc7519#section-4.1.4`,
			hasAccept: true,
			noDeref:   true,
		},
		{
			Name:      "issuedAt",
			JSONKey:   "iat",
			Type:      "*NumericDate",
			Comment:   `https://tools.ietf.org/html/rfc7519#section-4.1.6`,
			hasAccept: true,
			noDeref:   true,
		},
		{
			Name:    "issuer",
			JSONKey: "iss",
			Type:    "*string",
			Comment: `https://tools.ietf.org/html/rfc7519#section-4.1.1`,
		},
		{
			Name:    "jwtID",
			JSONKey: "jti",
			Type:    "*string",
			Comment: `https://tools.ietf.org/html/rfc7519#section-4.1.7`,
		},
		{
			Name:      "notBefore",
			JSONKey:   "nbf",
			Type:      "*NumericDate",
			Comment:   `https://tools.ietf.org/html/rfc7519#section-4.1.5`,
			hasAccept: true,
			noDeref:   true,
		},
		{
			Name:    "subject",
			JSONKey: "sub",
			Type:    "*string",
			Comment: `https://tools.ietf.org/html/rfc7519#section-4.1.2`,
		},
	}

	fmt.Fprintf(&buf, "\npackage jwt")
	fmt.Fprintf(&buf, "\n\nimport (")
	for _, pkg := range []string{"encoding/json", "time", "github.com/pkg/errors"} {
		fmt.Fprintf(&buf, "\n%s", strconv.Quote(pkg))
	}
	fmt.Fprintf(&buf, "\n)") // end of import

	fmt.Fprintf(&buf, "\n\n// Key names for standard claims")
	fmt.Fprintf(&buf, "\nconst (")
	for _, field := range fields {
		fmt.Fprintf(&buf, "\n%sKey = %s", field.UpperName(), strconv.Quote(field.JSONKey))
	}
	fmt.Fprintf(&buf, "\n)") // end const

	fmt.Fprintf(&buf, "\n\n// Token represents a JWT token. The object has convenience accessors")
	fmt.Fprintf(&buf, "\n// to %d standard claims including ", len(fields))
	for i, field := range fields {
		fmt.Fprintf(&buf, "%s", strconv.Quote(field.JSONKey))
		switch {
		case i < len(fields)-2:
			fmt.Fprintf(&buf, ", ")
		case i == len(fields)-2:
			fmt.Fprintf(&buf, ", and ")
		}
	}
	fmt.Fprintf(&buf, "\n// which are type-aware (to an extent). Other claims may be accessed via the `Get`/`Set`")
	fmt.Fprintf(&buf, "\n// methods but their types are not taken into consideration at all. If you have non-standard")
	fmt.Fprintf(&buf, "\n// claims that you must frequently access, consider wrapping the token in a wrapper")
	fmt.Fprintf(&buf, "\n// by embedding the jwt.Token type in it")
	fmt.Fprintf(&buf, "\ntype Token struct {")
	for _, field := range fields {
		fmt.Fprintf(&buf, "\n%s %s // %s", field.Name, field.Type, field.Comment)
	}
	fmt.Fprintf(&buf, "\nprivateClaims map[string]interface{}")
	fmt.Fprintf(&buf, "\n}") // end type Token

	fmt.Fprintf(&buf, "\n\nfunc (t *Token) Get(s string) (interface{}, bool) {")
	fmt.Fprintf(&buf, "\nswitch s {")
	for _, field := range fields {
		fmt.Fprintf(&buf, "\ncase %sKey:", field.UpperName())
		switch {
		case field.IsList():
			fmt.Fprintf(&buf, "\nif len(t.%s) == 0 {", field.Name)
			fmt.Fprintf(&buf, "\nreturn nil, false")
			fmt.Fprintf(&buf, "\n}") // end if len(t.%s) == 0
			fmt.Fprintf(&buf, "\nreturn t.%s, true", field.Name)
		case field.IsPointer():
			fmt.Fprintf(&buf, "\nif t.%s == nil {", field.Name)
			fmt.Fprintf(&buf, "\nreturn nil, false")
			fmt.Fprintf(&buf, "\n} else {")
			if field.noDeref {
				fmt.Fprintf(&buf, "\nreturn t.%s, true", field.Name)
			} else {
				fmt.Fprintf(&buf, "\nreturn *(t.%s), true", field.Name)
			}
			fmt.Fprintf(&buf, "\n}") // end if t.%s != nil
		}
	}
	fmt.Fprintf(&buf, "\n}") // end switch
	fmt.Fprintf(&buf, "\nif v, ok := t.privateClaims[s]; ok {")
	fmt.Fprintf(&buf, "\nreturn v, true")
	fmt.Fprintf(&buf, "\n}") // end if v, ok := t.privateClaims[s]
	fmt.Fprintf(&buf, "\nreturn nil, false")
	fmt.Fprintf(&buf, "\n}") // end of Get

	fmt.Fprintf(&buf, "\n\nfunc (t *Token) Set(name string, v interface{}) error {")
	fmt.Fprintf(&buf, "\nswitch name {")
	for _, field := range fields {
		fmt.Fprintf(&buf, "\ncase %sKey:", field.UpperName())
		switch {
		case field.hasAccept:
			if field.IsPointer() {
				fmt.Fprintf(&buf, "\nvar x %s", field.PointerElem())
			} else {
				fmt.Fprintf(&buf, "\nvar x %s", field.Type)
			}
			fmt.Fprintf(&buf, "\nif err := x.Accept(v); err != nil {")
			fmt.Fprintf(&buf, "\nreturn errors.Wrap(err, `invalid value for '%s' key`)", field.Name)
			fmt.Fprintf(&buf, "\n}")
			if field.IsPointer() {
				fmt.Fprintf(&buf, "\nt.%s = &x", field.Name)
			} else {
				fmt.Fprintf(&buf, "\nt.%s = x", field.Name)
			}
		case field.IsPointer():
			fmt.Fprintf(&buf, "\nx, ok := v.(%s)", field.PointerElem())
			fmt.Fprintf(&buf, "\nif !ok {")
			fmt.Fprintf(&buf, "\nreturn errors.Errorf(`invalid type for '%s' key: %%T`, v)", field.Name)
			fmt.Fprintf(&buf, "\n}") // end if !ok
			fmt.Fprintf(&buf, "\nt.%s = &x", field.Name)
		case field.IsList():
			fmt.Fprintf(&buf, "\nswitch x := v.(type) {")
			fmt.Fprintf(&buf, "\ncase %s:", field.ListElem())
			fmt.Fprintf(&buf, "\nt.%s = []string{x}", field.Name)
			fmt.Fprintf(&buf, "\ncase %s:", field.Type)
			fmt.Fprintf(&buf, "\nt.%s = x", field.Name)
			fmt.Fprintf(&buf, "\ndefault:")
			fmt.Fprintf(&buf, "\nreturn errors.Errorf(`invalid type for '%s' key: %%T`, v)", field.Name)
			fmt.Fprintf(&buf, "\n}") // end of switch x := v.(type) {")
		}
	}
	fmt.Fprintf(&buf, "\ndefault:")
	fmt.Fprintf(&buf, "\nt.privateClaims[name] = v")
	fmt.Fprintf(&buf, "\n}") // end switch
	fmt.Fprintf(&buf, "\nreturn nil")
	fmt.Fprintf(&buf, "\n}") // end func Set

	fmt.Fprintf(&buf, "\n\nfunc (t *Token) UnmarshalJSON(data []byte) error {")
	fmt.Fprintf(&buf, "\nm := make(map[string]interface{})")
	fmt.Fprintf(&buf, "\nif err := json.Unmarshal(data, &m); err != nil {")
	fmt.Fprintf(&buf, "\nreturn errors.Wrap(err, `failed to unmarshal claims`)")
	fmt.Fprintf(&buf, "\n}") // end if err := json.Unmarshal
	fmt.Fprintf(&buf, "\nt.privateClaims = make(map[string]interface{})")
	fmt.Fprintf(&buf, "\nfor k, v := range m {")
	fmt.Fprintf(&buf, "\nif err := t.Set(k, v); err != nil {")
	fmt.Fprintf(&buf, "\nreturn errors.Wrapf(err, `failed to set key '%%s'`, k)")
	fmt.Fprintf(&buf, "\n}") // end if err := t.Set(k, v)
	fmt.Fprintf(&buf, "\n}") // end for k, v := range m 
	fmt.Fprintf(&buf, "\nreturn nil")
	fmt.Fprintf(&buf, "\n}") // end UnmarshalJSON

	fmt.Fprintf(&buf, "\n\nfunc (t Token) MarshalJSON() ([]byte, error) {")
	fmt.Fprintf(&buf, "\nm := make(map[string]interface{})")
	fmt.Fprintf(&buf, "\nfor k, v := range t.privateClaims {")
	fmt.Fprintf(&buf, "\nm[k] = v")
	fmt.Fprintf(&buf, "\n}") // for k, v := range t.privateClaims

	for _, field := range fields {
		switch {
		case field.IsList():
			fmt.Fprintf(&buf, "\n\nif l := len(t.%s); l > 0 {", field.Name)
			fmt.Fprintf(&buf, "\nswitch l {")
			fmt.Fprintf(&buf, "\ncase 0:")
			fmt.Fprintf(&buf, "\n// no op")
			fmt.Fprintf(&buf, "\ncase 1:")
			fmt.Fprintf(&buf, "\nm[%sKey] = t.%s[0]", field.UpperName(), field.Name)
			fmt.Fprintf(&buf, "\ndefault:")
			fmt.Fprintf(&buf, "\nm[%sKey] = t.%s", field.UpperName(), field.Name)
			fmt.Fprintf(&buf, "\n}") // end switch
			fmt.Fprintf(&buf, "\n}") // end if l := len()
		case field.IsPointer():
			fmt.Fprintf(&buf, "\n\nif v := t.%s; v != nil {", field.Name)
			fmt.Fprintf(&buf, "\nm[%sKey] = *v", field.UpperName())
			fmt.Fprintf(&buf, "\n}") // end if v := t.%s
		default:
			return errors.Errorf(`don't know how to handle field %+v`, field)
		}
	}
	fmt.Fprintf(&buf, "\n\nreturn json.Marshal(m)")
	fmt.Fprintf(&buf, "\n}") // end func MarshalJSON

	for _, field := range fields {
		switch {
		case field.IsList():
			fmt.Fprintf(&buf, "\n\nfunc (t Token) %s() %s {", field.UpperName(), field.ListElem())
			fmt.Fprintf(&buf, "\nif v, ok := t.Get(%sKey); ok {", field.UpperName())
			fmt.Fprintf(&buf, "\nreturn (v.(%s))[0]", field.Type)
			fmt.Fprintf(&buf, "\n}") // end if v, ok := t.Get(%sKey)
			fmt.Fprintf(&buf, "\nreturn %s", zeroval(field.ListElem()))
			fmt.Fprintf(&buf, "\n}") // end func (t Token) %s() %s
		case field.Type == "*NumericDate":
			fmt.Fprintf(&buf, "\n\nfunc (t Token) %s() time.Time {", field.UpperName())
			fmt.Fprintf(&buf, "\nreturn timeFromNumericDateClaim(&t, %sKey)", field.UpperName())
			fmt.Fprintf(&buf, "\n}") // end func (t Token) %s()
		case field.IsPointer():
			fmt.Fprintf(&buf, "\n\nfunc (t Token) %s() %s {", field.UpperName(), field.PointerElem())
			fmt.Fprintf(&buf, "\nif v, ok := t.Get(%sKey); ok {", field.UpperName())
			fmt.Fprintf(&buf, "\nreturn v.(%s)", field.PointerElem())
			fmt.Fprintf(&buf, "\n}") // end if v, ok := t.Get(%sKey)
			fmt.Fprintf(&buf, "\nreturn %s", zeroval(field.PointerElem()))
			fmt.Fprintf(&buf, "\n}") // end func (t Token) %s() %s
		}
	}

	fmt.Fprintf(&buf, "\n\nfunc timeFromNumericDateClaim(t *Token, key string) time.Time {")
	fmt.Fprintf(&buf, "\nv, ok := t.Get(key)")
	fmt.Fprintf(&buf, "\nif !ok {")
	fmt.Fprintf(&buf, "\nreturn time.Time{}")
	fmt.Fprintf(&buf, "\n}") // end if !ok
	fmt.Fprintf(&buf, "\n\nswitch x := v.(type) {")
	fmt.Fprintf(&buf, "\ncase time.Time:")
	fmt.Fprintf(&buf, "\nreturn x")
	fmt.Fprintf(&buf, "\ncase *NumericDate:")
	fmt.Fprintf(&buf, "\nreturn x.Time")
	fmt.Fprintf(&buf, "\ndefault:")
	fmt.Fprintf(&buf, "\nreturn time.Time{}")
	fmt.Fprintf(&buf, "\n}") // end switch x
	fmt.Fprintf(&buf, "\n}") // end func (t *Token) timeFromNumericDate

	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		log.Printf("%s", buf.Bytes())
		log.Printf("%s", err)
		return errors.Wrap(err, `failed to format source`)
	}

	filename := "token_gen.go"
	f, err := os.Create(filename)
	if err != nil {
		return errors.Wrapf(err, `failed to open file %s for writing`, filename)
	}
	defer f.Close()

	f.Write(formatted)
	return nil
}
