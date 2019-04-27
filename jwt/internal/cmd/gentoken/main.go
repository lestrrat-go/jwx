package main

import (
	"bytes"
	"fmt"
	"go/format"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/pkg/errors"
)

func main() {
	if err := _main(); err != nil {
		log.Printf("%s", err)
		os.Exit(1)
	}
}

func _main() error {
	if err := generateJwtToken(); err != nil {
		return errors.Wrap(err, `failed to generate token file`)
	}
	if err := generateOpenID(); err != nil {
		return errors.Wrap(err, `failed to generate openid API`)
	}
	if err := generateOpenIDAddress(); err != nil {
		return errors.Wrap(err, `failed to generate openid address`)
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
	var buf bytes.Buffer
	var upnext bool
	for _, r := range strings.Title(t.Name) {
		if r == '_' {
			upnext = true
			continue
		}
		if upnext {
			r = unicode.ToUpper(r)
		}
		buf.WriteRune(r)
		upnext = false
	}

	return buf.String()
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
	`string`:      `""`,
	`bool`:        `false`,
	`NumericDate`: `time.Time{}`,
}

func zeroval(s string) string {
	if v, ok := zerovals[s]; ok {
		return v
	}
	return `nil`
}

func generateOpenIDAddress() error {
	var fields = []*tokenField{
		{
			Name:    "formatted",
			Type:    "*string",
			Comment: "https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim",
		},
		{
			Name:    "streetAddress",
			JSONKey: "street_address",
			Type:    "*string",
			Comment: "https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim",
		},
		{
			Name:    "locality",
			Type:    "*string",
			Comment: "https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim",
		},
		{
			Name:    "region",
			Type:    "*string",
			Comment: "https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim",
		},
		{
			Name:    "postalCode",
			JSONKey: "postal_code",
			Type:    "*string",
			Comment: "https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim",
		},
		{
			Name:    "country",
			Type:    "*string",
			Comment: "https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim",
		},
	}

	for _, field := range fields {
		if field.JSONKey == "" {
			field.JSONKey = field.Name
		}
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "\n// This file is auto-generated. DO NOT EDIT")
	fmt.Fprintf(&buf, "\npackage openid")

	fmt.Fprintf(&buf, "\n\nimport (")
	for _, pkg := range []string{"bytes", "encoding/json", "github.com/pkg/errors"} {
		fmt.Fprintf(&buf, "\n%s", strconv.Quote(pkg))
	}

	fmt.Fprintf(&buf, "\n)") // end of import
	fmt.Fprintf(&buf, "\nconst (")
	for _, field := range fields {
		fmt.Fprintf(&buf, "\nAddress%sKey = %#v", field.UpperName(), field.JSONKey)
	}
	fmt.Fprintf(&buf, "\n)")

	fmt.Fprintf(&buf, "\n\n// AddressClaim is the address claim as described in https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim")
	fmt.Fprintf(&buf, "\ntype AddressClaim struct {")
	for _, field := range fields {
		fmt.Fprintf(&buf, "\n%s %s // %s", field.Name, field.Type, field.Comment)
	}
	fmt.Fprintf(&buf, "\n}")

	for _, field := range fields {
		writeAccessor(&buf, "AddressClaim", field)
	}

	writeGetMethod(&buf, "AddressClaim", fields, false)

	fmt.Fprintf(&buf, "\nfunc (a *AddressClaim) Set(key string, value interface{}) error {")
	fmt.Fprintf(&buf, "\nswitch key {")
	for _, field := range fields {
		fmt.Fprintf(&buf, "\ncase Address%sKey:", field.UpperName())
		fmt.Fprintf(&buf, "\nv, ok := value.(%s)", field.PointerElem())
		fmt.Fprintf(&buf, "\nif ok {")
		fmt.Fprintf(&buf, "\na.%s = &v", field.Name)
		fmt.Fprintf(&buf, "\nreturn nil")
		fmt.Fprintf(&buf, "\n}")
		fmt.Fprintf(&buf, "\nreturn errors.Errorf(`invalid type for key '%s': %%T`, value)", field.Name)
	}
	fmt.Fprintf(&buf, "\ndefault:")
	fmt.Fprintf(&buf, "\nreturn errors.Errorf(`invalid key for address claim: %%s`, key)")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\n}")

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
	if err := writeJSONMarshaler(&buf, "AddressClaim", fields, false); err != nil {
		return errors.Wrap(err, `failed to write JSON marshaler interface`)
	}

	return writeFormattedSource(&buf, filepath.Join("openid", "address_gen.go"), buf.Bytes())
}

func generateOpenID() error {
	var fields = []*tokenField{
		{
			Name:    "name",
			Type:    "string",
			Comment: "https://openid.net/specs/openid-connect-core-1_0.html",
		},
		{
			Name:    "given_name",
			Type:    "string",
			Comment: "https://openid.net/specs/openid-connect-core-1_0.html",
		},
		{
			Name:    "middle_name",
			Type:    "string",
			Comment: "https://openid.net/specs/openid-connect-core-1_0.html",
		},
		{
			Name:    "family_name",
			Type:    "string",
			Comment: "https://openid.net/specs/openid-connect-core-1_0.html",
		},
		{
			Name:    "nickname",
			Type:    "string",
			Comment: "https://openid.net/specs/openid-connect-core-1_0.html",
		},
		{
			Name:    "preferred_username",
			Type:    "string",
			Comment: "https://openid.net/specs/openid-connect-core-1_0.html",
		},
		{
			Name:    "profile",
			Type:    "string",
			Comment: "https://openid.net/specs/openid-connect-core-1_0.html",
		},
		{
			Name:    "picture",
			Type:    "string",
			Comment: "https://openid.net/specs/openid-connect-core-1_0.html",
		},
		{
			Name:    "website",
			Type:    "string",
			Comment: "https://openid.net/specs/openid-connect-core-1_0.html",
		},
		{
			Name:    "email",
			Type:    "string",
			Comment: "https://openid.net/specs/openid-connect-core-1_0.html",
		},
		{
			Name:    "email_verified",
			Type:    "bool",
			Comment: "https://openid.net/specs/openid-connect-core-1_0.html",
		},
		{
			Name:    "gender",
			Type:    "string",
			Comment: "https://openid.net/specs/openid-connect-core-1_0.html",
		},
		{
			Name:    "birthdate",
			Type:    "*BirthdateClaim",
			Comment: "https://openid.net/specs/openid-connect-core-1_0.html",
		},
		{
			Name:    "zoneinfo",
			Type:    "string",
			Comment: "https://openid.net/specs/openid-connect-core-1_0.html",
		},
		{
			Name:    "locale",
			Type:    "string",
			Comment: "https://openid.net/specs/openid-connect-core-1_0.html",
		},
		{
			Name:    "phone_number",
			Type:    "string",
			Comment: "https://openid.net/specs/openid-connect-core-1_0.html",
		},
		{
			Name:    "phone_number_verified",
			Type:    "bool",
			Comment: "https://openid.net/specs/openid-connect-core-1_0.html",
		},
		{
			Name:    "address",
			Type:    "*AddressClaim",
			Comment: "https://openid.net/specs/openid-connect-core-1_0.html",
		},
		{
			Name:    "updated_at",
			Type:    "*types.NumericDate",
			Comment: "https://openid.net/specs/openid-connect-core-1_0.html",
		},
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "\n// This file is auto-generated. DO NOT EDIT")
	fmt.Fprintf(&buf, "\npackage openid")

	fmt.Fprintf(&buf, "\n\nimport (")
	for _, pkg := range []string{"github.com/lestrrat-go/jwx/jwt"} {
		fmt.Fprintf(&buf, "\n%s", strconv.Quote(pkg))
	}
	fmt.Fprintf(&buf, "\n)") // end of import

	fmt.Fprintf(&buf, "\nconst (")
	for _, field := range fields {
		fmt.Fprintf(&buf, "\n%sKey = %#v", field.UpperName(), field.Name)
	}
	fmt.Fprintf(&buf, "\n)")

	fmt.Fprintf(&buf, "\ntype Token interface {")
	fmt.Fprintf(&buf, "\nGet(string) (interface{}, bool)")
	fmt.Fprintf(&buf, "\nSet(string, interface{}) error")
	fmt.Fprintf(&buf, "\n}")

	for _, field := range fields {
		fmt.Fprintf(&buf, "\n// %s returns the value of `%s` claim. If the claim does not exist, the zero value will be returned.", field.UpperName(), field.Name)
		fmt.Fprintf(&buf, "\nfunc %s(t Token) %s {", field.UpperName(), field.Type)
		fmt.Fprintf(&buf, "\nv, _ := t.Get(%sKey)", field.UpperName())
		fmt.Fprintf(&buf, "\nif s, ok := v.(%s); ok {", field.Type)
		fmt.Fprintf(&buf, "\nreturn s")
		fmt.Fprintf(&buf, "\n}")
		fmt.Fprintf(&buf, "\nreturn %v", zeroval(field.Type))
		fmt.Fprintf(&buf, "\n}")
	}

	return writeFormattedSource(&buf, filepath.Join("openid", "openid_gen.go"), buf.Bytes())
}

func generateJwtToken() error {
	var buf bytes.Buffer

	var fields = []*tokenField{
		{
			Name:      "audience",
			JSONKey:   "aud",
			Type:      "StringList",
			Comment:   `https://tools.ietf.org/html/rfc7519#section-4.1.3`,
			isList:    true,
			hasAccept: true,
		},
		{
			Name:      "expiration",
			JSONKey:   "exp",
			Type:      "*types.NumericDate",
			Comment:   `https://tools.ietf.org/html/rfc7519#section-4.1.4`,
			hasAccept: true,
			noDeref:   true,
		},
		{
			Name:      "issuedAt",
			JSONKey:   "iat",
			Type:      "*types.NumericDate",
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
			Type:      "*types.NumericDate",
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

	sort.Slice(fields, func(i, j int) bool {
		return fields[i].Name < fields[j].Name
	})
	for _, field := range fields {
		if field.JSONKey == "" {
			field.JSONKey = field.Name
		}
	}

	fmt.Fprintf(&buf, "\n// This file is auto-generated. DO NOT EDIT")
	fmt.Fprintf(&buf, "\npackage jwt")
	fmt.Fprintf(&buf, "\n\nimport (")
	for _, pkg := range []string{"bytes", "encoding/json", "github.com/pkg/errors", "github.com/lestrrat-go/jwx/jwt/internal/types"} {
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
			fmt.Fprintf(&buf, " and ")
		}
	}
	fmt.Fprintf(&buf, "\n// which are type-aware (to an extent). Other claims may be accessed via the `Get`/`Set`")
	fmt.Fprintf(&buf, "\n// methods but their types are not taken into consideration at all. If you have non-standard")
	fmt.Fprintf(&buf, "\n// claims that you must frequently access, consider wrapping the token in a wrapper")
	fmt.Fprintf(&buf, "\n// by embedding the jwt.Token type in it")
	fmt.Fprintf(&buf, "\ntype Token struct {")
	for _, field := range fields {
		fmt.Fprintf(&buf, "\n%s %s `json:\"%s,omitempty\"` // %s", field.Name, field.Type, field.JSONKey, field.Comment)
	}
	fmt.Fprintf(&buf, "\nprivateClaims map[string]interface{} `json:\"-\"`")
	fmt.Fprintf(&buf, "\n}") // end type Token
	writeGetMethod(&buf, "Token", fields, true)

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
	fmt.Fprintf(&buf, "\nif t.privateClaims == nil {")
	fmt.Fprintf(&buf, "\nt.privateClaims = make(map[string]interface{})")
	fmt.Fprintf(&buf, "\n}") // end if h.privateParams == nil
	fmt.Fprintf(&buf, "\nt.privateClaims[name] = v")
	fmt.Fprintf(&buf, "\n}") // end switch name
	fmt.Fprintf(&buf, "\nreturn nil")
	fmt.Fprintf(&buf, "\n}") // end func (h *StandardHeaders) Set(name string, value interface{})

	for _, field := range fields {
		writeAccessor(&buf, "Token", field)
	}

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

	if err := writeJSONMarshaler(&buf, "Token", fields, true); err != nil {
		return errors.Wrap(err, `failed to write JSON marshaler interface`)
	}

	if err := writeFormattedSource(&buf, "token_gen.go", buf.Bytes()); err != nil {
		return errors.Wrap(err, `failed to write formatted source code`)
	}
	return nil
}

func writeAccessor(dst io.Writer, typ string, field *tokenField) error {
	keyName := field.UpperName() + "Key"
	if typ == "AddressClaim" {
		keyName = "Address" + keyName
	}

	fmt.Fprintf(dst, "\n\n// %s is a convenience function to retrieve the corresponding value store in the token", field.UpperName())
	fmt.Fprintf(dst, "\n// if there is a problem retrieving the value, the zero value is returned. If you need to differentiate between existing/non-existing values, use `Get` instead")
	switch {
	case field.Type == "*NumericDate" || field.Type == "*jwt.NumericDate":
		fmt.Fprintf(dst, "\nfunc (t %s) %s() time.Time {", typ, field.UpperName())
		fmt.Fprintf(dst, "\nif v, ok := t.Get(%s); ok {", keyName)
		fmt.Fprintf(dst, "\nreturn v.(time.Time)")
		fmt.Fprintf(dst, "\n}")
		fmt.Fprintf(dst, "\nreturn time.Time{}")
		fmt.Fprintf(dst, "\n}") // end func (t %s) %s()
	case field.IsPointer():
		fmt.Fprintf(dst, "\nfunc (t %s) %s() %s {", typ, field.UpperName(), field.PointerElem())
		fmt.Fprintf(dst, "\nif v, ok := t.Get(%s); ok {", keyName)
		fmt.Fprintf(dst, "\nreturn v.(%s)", field.PointerElem())
		fmt.Fprintf(dst, "\n}") // end if v, ok := t.Get(%s)
		fmt.Fprintf(dst, "\nreturn %s", zeroval(field.PointerElem()))
		fmt.Fprintf(dst, "\n}") // end func (t %s) %s() %s
	default:
		fmt.Fprintf(dst, "\nfunc (t %s) %s() %s {", typ, field.UpperName(), field.Type)
		fmt.Fprintf(dst, "\nif v, ok := t.Get(%s); ok {", keyName)
		fmt.Fprintf(dst, "\nreturn v.([]string)")
		fmt.Fprintf(dst, "\n}") // end if v, ok := t.Get(%s)
		fmt.Fprintf(dst, "\nreturn %s", zeroval(field.Type))
		fmt.Fprintf(dst, "\n}") // end func (t %s) %s() %s
	}
	return nil
}

func writeJSONMarshaler(dst io.Writer, typ string, fields []*tokenField, hasPrivateClaims bool) error {
	fmt.Fprintf(dst, "\n\n// MarshalJSON serializes the token in JSON format.")
	fmt.Fprintf(dst, "\nfunc (t %s) MarshalJSON() ([]byte, error) {", typ)
	fmt.Fprintf(dst, "\nvar buf bytes.Buffer")
	fmt.Fprintf(dst, "\nbuf.WriteRune('{')")

	for i, field := range fields {
		if strings.HasPrefix(field.Type, "*") {
			fmt.Fprintf(dst, "\nif t.%s != nil {", field.Name)
		} else {
			fmt.Fprintf(dst, "\nif len(t.%s) > 0 {", field.Name)
		}
		if i > 0 {
			fmt.Fprintf(dst, "\nif buf.Len() > 1 {")
			fmt.Fprintf(dst, "\nbuf.WriteRune(',')")
			fmt.Fprintf(dst, "\n}")
		}
		fmt.Fprintf(dst, "\nbuf.WriteRune('\"')")
		fmt.Fprintf(dst, "\nbuf.WriteString(")
		if typ == "AddressClaim" {
			fmt.Fprintf(dst, "Address")
		}
		fmt.Fprintf(dst, "%sKey)", field.UpperName())
		fmt.Fprintf(dst, "\nbuf.WriteString(`\":`)")
		fmt.Fprintf(dst, "\nif err := writeJSON(&buf, t.%s, ", field.Name)
		if typ == "AddressClaim" {
			fmt.Fprintf(dst, "Address")
		}
		fmt.Fprintf(dst, "%sKey); err != nil {", field.UpperName())
		fmt.Fprintf(dst, "\nreturn nil, err")
		fmt.Fprintf(dst, "\n}")
		fmt.Fprintf(dst, "\n}")
	}

	if !hasPrivateClaims {
		fmt.Fprintf(dst, "\nbuf.WriteRune('}')")
	} else {
		fmt.Fprintf(dst, "\nif len(t.privateClaims) == 0 {")
		fmt.Fprintf(dst, "\nbuf.WriteRune('}')")
		fmt.Fprintf(dst, "\nreturn buf.Bytes(), nil")
		fmt.Fprintf(dst, "\n}")

		fmt.Fprintf(dst, "\n// If private claims exist, they need to flattened and included in the token")
		fmt.Fprintf(dst, "\npcjson, err := json.Marshal(t.privateClaims)")
		fmt.Fprintf(dst, "\nif err != nil {")
		fmt.Fprintf(dst, "\nreturn nil, errors.Wrap(err, `failed to marshal private claims`)")
		fmt.Fprintf(dst, "\n}")

		fmt.Fprintf(dst, "\n// remove '{' from the private claims")
		fmt.Fprintf(dst, "\npcjson = pcjson[1:]")
		fmt.Fprintf(dst, "\nif buf.Len() > 1 {")
		fmt.Fprintf(dst, "\nbuf.WriteRune(',')")
		fmt.Fprintf(dst, "\n}")
		fmt.Fprintf(dst, "\nbuf.Write(pcjson)")
	}
	fmt.Fprintf(dst, "\nreturn buf.Bytes(), nil")
	fmt.Fprintf(dst, "\n}")

	fmt.Fprintf(dst, "\n\n// UnmarshalJSON deserializes data from a JSON data buffer into a %s", typ)
	fmt.Fprintf(dst, "\nfunc (t *%s) UnmarshalJSON(data []byte) error {", typ)
	fmt.Fprintf(dst, "\nvar m map[string]interface{}")
	fmt.Fprintf(dst, "\nif err := json.Unmarshal(data, &m); err != nil {")
	fmt.Fprintf(dst, "\nreturn errors.Wrap(err, `failed to unmarshal token`)")
	fmt.Fprintf(dst, "\n}")
	fmt.Fprintf(dst, "\nfor name, value := range m {")
	fmt.Fprintf(dst, "\nif err := t.Set(name, value); err != nil {")
	fmt.Fprintf(dst, "\nreturn errors.Wrapf(err, `failed to set value for %%s`, name)")
	fmt.Fprintf(dst, "\n}")
	fmt.Fprintf(dst, "\n}")
	fmt.Fprintf(dst, "\nreturn nil")
	fmt.Fprintf(dst, "\n}")

	return nil
}

func writeFormattedSource(dst io.Writer, filename string, data []byte) error {
	log.Printf("Attempting to write to %s", filename)
	formatted, err := format.Source(data)
	if err != nil {
		log.Printf("%s", data)
		log.Printf("%s", err)
		return errors.Wrap(err, `failed to format source`)
	}

	f, err := os.Create(filename)
	if err != nil {
		return errors.Wrapf(err, `failed to open file %s for writing`, filename)
	}
	defer f.Close()

	_, err = f.Write(formatted)
	return err
}

func writeGetMethod(dst io.Writer, typ string, fields []*tokenField, hasPrivateClaims bool) error {

	fmt.Fprintf(dst, "\n\nfunc (t *%s) Get(s string) (interface{}, bool) {", typ)
	fmt.Fprintf(dst, "\nswitch s {")
	for _, field := range fields {
		keyName := field.UpperName() + "Key"
		if typ == "AddressClaim" {
			keyName = "Address" + keyName
		}
		fmt.Fprintf(dst, "\ncase %s:", keyName)
		switch {
		case field.IsList():
			fmt.Fprintf(dst, "\nif len(t.%s) == 0 {", field.Name)
			fmt.Fprintf(dst, "\nreturn nil, false")
			fmt.Fprintf(dst, "\n}") // end if len(t.%s) == 0
			fmt.Fprintf(dst, "\nreturn ")
			// some types such as `aud` need explicit conversion
			var pre, post string
			if field.Type == "StringList" {
				pre = "[]string("
				post = ")"
			}
			fmt.Fprintf(dst, "%st.%s%s, true", pre, field.Name, post)
		case field.IsPointer():
			fmt.Fprintf(dst, "\nif t.%s == nil {", field.Name)
			fmt.Fprintf(dst, "\nreturn nil, false")
			fmt.Fprintf(dst, "\n} else {")
			if field.noDeref {
				if field.Type == "*NumericDate" {
					fmt.Fprintf(dst, "\nreturn t.%s.Get(), true", field.Name)
				} else {
					fmt.Fprintf(dst, "\nreturn t.%s, true", field.Name)
				}
			} else {
				fmt.Fprintf(dst, "\nreturn *(t.%s), true", field.Name)
			}
			fmt.Fprintf(dst, "\n}") // end if t.%s != nil
		default:
			fmt.Fprintf(dst, "\nreturn t.%s, true", field.Name)
		}
	}
	fmt.Fprintf(dst, "\n}") // end switch
	if hasPrivateClaims {
		fmt.Fprintf(dst, "\nif v, ok := t.privateClaims[s]; ok {")
		fmt.Fprintf(dst, "\nreturn v, true")
		fmt.Fprintf(dst, "\n}") // end if v, ok := t.privateClaims[s]
	}

	fmt.Fprintf(dst, "\nreturn nil, false")
	fmt.Fprintf(dst, "\n}") // end of Get
	return nil
}
