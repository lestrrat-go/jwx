package main

import (
	"bytes"
	"fmt"
	"go/format"
	"log"
	"os"
	"sort"
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
	return generateHeaders()
}

type headerField struct {
	name       string
	method     string
	typ        string
	returnType string
	key        string
	comment    string
	hasAccept  bool
	hasGet     bool
	noDeref    bool
	isList     bool
}

func (f headerField) IsList() bool {
	return f.isList || strings.HasPrefix(f.typ, "[]")
}

func (f headerField) IsPointer() bool {
	return strings.HasPrefix(f.typ, "*")
}

func (f headerField) PointerElem() string {
	return strings.TrimPrefix(f.typ, "*")
}

var zerovals = map[string]string{
	"string":      `""`,
	"jwa.KeyType": "jwa.InvalidKeyType",
}

func zeroval(s string) string {
	if v, ok := zerovals[s]; ok {
		return v
	}
	return "nil"
}

func generateHeaders() error {
	fields := []headerField{
		{
			name:      `keyType`,
			method:    `KeyType`,
			typ:       `*jwa.KeyType`,
			key:       `kty`,
			comment:   `https://tools.ietf.org/html/rfc7517#section-4.1`,
			hasAccept: true,
		},
		{
			name:    `keyUsage`,
			method:  `KeyUsage`,
			key:     `use`,
			typ:     `*string`,
			comment: `https://tools.ietf.org/html/rfc7517#section-4.2`,
		},
		{
			name:      `keyops`,
			method:    `KeyOps`,
			typ:       `KeyOperationList`,
			key:       `key_ops`,
			comment:   `https://tools.ietf.org/html/rfc7517#section-4.3`,
			hasAccept: true,
		},
		{
			name:    `algorithm`,
			method:  `Algorithm`,
			typ:     `*string`,
			key:     `alg`,
			comment: `https://tools.ietf.org/html/rfc7517#section-4.4`,
		},
		{
			name:    `keyID`,
			method:  `KeyID`,
			typ:     `*string`,
			key:     `kid`,
			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.4`,
		},
		{
			name:    `x509URL`,
			method:  `X509URL`,
			typ:     `*string`,
			key:     `x5u`,
			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.5`,
		},
		{
			name:       `x509CertChain`,
			method:     `X509CertChain`,
			typ:        `*CertificateChain`,
			key:        `x5c`,
			comment:    `https://tools.ietf.org/html/rfc7515#section-4.1.6`,
			hasAccept:  true,
			hasGet:     true,
			noDeref:    true,
			returnType: `[]*x509.Certificate`,
		},
		{
			name:    `x509CertThumbprint`,
			method:  `X509CertThumbprint`,
			typ:     `*string`,
			key:     `x5t`,
			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.7`,
		},
		{
			name:    `x509CertThumbprintS256`,
			method:  `X509CertThumbprintS256`,
			typ:     `*string`,
			key:     `x5t#S256`,
			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.8`,
		},
	}

	sort.Slice(fields, func(i, j int) bool {
		return fields[i].name < fields[j].name
	})

	var buf bytes.Buffer

	fmt.Fprintf(&buf, "\n// This file is auto-generated. DO NOT EDIT")
	fmt.Fprintf(&buf, "\n\npackage jwk")
	fmt.Fprintf(&buf, "\n\nimport (")
	for _, pkg := range []string{"crypto/x509", "fmt"} {
		fmt.Fprintf(&buf, "\n%s", strconv.Quote(pkg))
	}
	fmt.Fprintf(&buf, "\n\n")
	for _, pkg := range []string{"github.com/lestrrat-go/jwx/jwa", "github.com/pkg/errors"} {
		fmt.Fprintf(&buf, "\n%s", strconv.Quote(pkg))
	}
	fmt.Fprintf(&buf, "\n)")

	fmt.Fprintf(&buf, "\n\nconst (")
	for _, f := range fields {
		fmt.Fprintf(&buf, "\n%sKey = %s", f.method, strconv.Quote(f.key))
	}
	fmt.Fprintf(&buf, "\n)") // end const

	fmt.Fprintf(&buf, "\n\ntype Headers interface {")
	fmt.Fprintf(&buf, "\nRemove(string)")
	fmt.Fprintf(&buf, "\nGet(string) (interface{}, bool)")
	fmt.Fprintf(&buf, "\nSet(string, interface{}) error")
	fmt.Fprintf(&buf, "\nPopulateMap(map[string]interface{}) error")
	fmt.Fprintf(&buf, "\nExtractMap(map[string]interface{}) error")
	fmt.Fprintf(&buf, "\nWalk(func(string, interface{}) error) error")
	for _, f := range fields {
		fmt.Fprintf(&buf, "\n%s() ", f.method)
		if f.returnType != "" {
			fmt.Fprintf(&buf, "%s", f.returnType)
		} else if f.IsPointer() && f.noDeref {
			fmt.Fprintf(&buf, "%s", f.typ)
		} else {
			fmt.Fprintf(&buf, "%s", f.PointerElem())
		}
	}
	fmt.Fprintf(&buf, "\n}") // end type Headers interface
	fmt.Fprintf(&buf, "\n\ntype StandardHeaders struct {")
	for _, f := range fields {
		fmt.Fprintf(&buf, "\n%s %s // %s", f.name, f.typ, f.comment)
	}
	fmt.Fprintf(&buf, "\nprivateParams map[string]interface{}")
	fmt.Fprintf(&buf, "\n}") // end type StandardHeaders

	fmt.Fprintf(&buf, "\n\nfunc (h *StandardHeaders) Remove(s string) {")
	fmt.Fprintf(&buf, "\ndelete(h.privateParams, s)")
	fmt.Fprintf(&buf, "\n}") // func Remove(s string)

	for _, f := range fields {
		fmt.Fprintf(&buf, "\n\nfunc (h *StandardHeaders) %s() ", f.method)
		if f.returnType != "" {
			fmt.Fprintf(&buf, "%s", f.returnType)
		} else if f.IsPointer() && f.noDeref {
			fmt.Fprintf(&buf, "%s", f.typ)
		} else {
			fmt.Fprintf(&buf, "%s", f.PointerElem())
		}
		fmt.Fprintf(&buf, " {")

		if f.hasGet {
			fmt.Fprintf(&buf, "\nreturn h.%s.Get()", f.name)
		} else if !f.IsPointer() {
			fmt.Fprintf(&buf, "\nreturn h.%s", f.name)
		} else {
			fmt.Fprintf(&buf, "\nif v := h.%s; v != %s {", f.name, zeroval(f.typ))
			if f.IsPointer() && !f.noDeref {
				fmt.Fprintf(&buf, "\nreturn *v")
			} else {
				fmt.Fprintf(&buf, "\nreturn v")
			}
			fmt.Fprintf(&buf, "\n}") // if h.%s != %s
			fmt.Fprintf(&buf, "\nreturn %s", zeroval(f.PointerElem()))
		}
		fmt.Fprintf(&buf, "\n}") // func (h *StandardHeaders) %s() %s
	}

	fmt.Fprintf(&buf, "\n\nfunc (h *StandardHeaders) Get(name string) (interface{}, bool) {")
	fmt.Fprintf(&buf, "\nswitch name {")
	for _, f := range fields {
		fmt.Fprintf(&buf, "\ncase %sKey:", f.method)
		fmt.Fprintf(&buf, "\nv := h.%s", f.name)
		if f.IsList() {
			fmt.Fprintf(&buf, "\nif len(v) == 0 {")
		} else {
			fmt.Fprintf(&buf, "\nif v == %s {", zeroval(f.typ))
		}
		fmt.Fprintf(&buf, "\nreturn nil, false")
		fmt.Fprintf(&buf, "\n}") // end if h.%s == nil
		if f.hasGet {
			fmt.Fprintf(&buf, "\nreturn v.Get(), true")
		} else if f.IsPointer() && !f.noDeref {
			fmt.Fprintf(&buf, "\nreturn *v, true")
		} else {
			fmt.Fprintf(&buf, "\nreturn v, true")
		}
	}
	fmt.Fprintf(&buf, "\ndefault:")
	fmt.Fprintf(&buf, "\nv, ok := h.privateParams[name]")
	fmt.Fprintf(&buf, "\nreturn v, ok")
	fmt.Fprintf(&buf, "\n}") // end switch name
	fmt.Fprintf(&buf, "\n}") // func (h *StandardHeaders) Get(name string) (interface{}, bool)

	fmt.Fprintf(&buf, "\n\nfunc (h *StandardHeaders) Set(name string, value interface{}) error {")
	fmt.Fprintf(&buf, "\nswitch name {")
	for _, f := range fields {
		fmt.Fprintf(&buf, "\ncase %sKey:", f.method)
		if f.name == "algorithm" {
			fmt.Fprintf(&buf, "\nswitch v := value.(type) {")
			fmt.Fprintf(&buf, "\ncase string:")
			fmt.Fprintf(&buf, "\nh.algorithm = &v")
			fmt.Fprintf(&buf, "\nreturn nil")
			fmt.Fprintf(&buf, "\ncase fmt.Stringer:")
			fmt.Fprintf(&buf, "\ns := v.String()")
			fmt.Fprintf(&buf, "\nh.algorithm = &s")
			fmt.Fprintf(&buf, "\nreturn nil")
			fmt.Fprintf(&buf, "\n}")
			fmt.Fprintf(&buf, "\nreturn errors.Errorf(`invalid value for %%s key: %%T`, AlgorithmKey, value)")
		} else if f.hasAccept {
			if f.IsPointer() {
				fmt.Fprintf(&buf, "\nvar acceptor %s", f.PointerElem())
				fmt.Fprintf(&buf, "\nif err := acceptor.Accept(value); err != nil {")
				fmt.Fprintf(&buf, "\nreturn errors.Wrapf(err, `invalid value for %%s key`, %sKey)", f.method)
				fmt.Fprintf(&buf, "\n}") // end if err := h.%s.Accept(value)
				fmt.Fprintf(&buf, "\nh.%s = &acceptor", f.name)
			} else {
				fmt.Fprintf(&buf, "\nif err := h.%s.Accept(value); err != nil {", f.name)
				fmt.Fprintf(&buf, "\nreturn errors.Wrapf(err, `invalid value for %%s key`, %sKey)", f.method)
				fmt.Fprintf(&buf, "\n}") // end if err := h.%s.Accept(value)
			}
			fmt.Fprintf(&buf, "\nreturn nil")
		} else {
			if f.IsPointer() {
				fmt.Fprintf(&buf, "\nif v, ok := value.(%s); ok {", f.PointerElem())
				fmt.Fprintf(&buf, "\nh.%s = &v", f.name)
			} else {
				fmt.Fprintf(&buf, "\nif v, ok := value.(%s); ok {", f.typ)
				fmt.Fprintf(&buf, "\nh.%s = v", f.name)
			}
			fmt.Fprintf(&buf, "\nreturn nil")
			fmt.Fprintf(&buf, "\n}") // end if v, ok := value.(%s)
			fmt.Fprintf(&buf, "\nreturn errors.Errorf(`invalid value for %%s key: %%T`, %sKey, value)", f.method)
		}
	}
	fmt.Fprintf(&buf, "\ndefault:")
	fmt.Fprintf(&buf, "\nif h.privateParams == nil {")
	fmt.Fprintf(&buf, "\nh.privateParams = map[string]interface{}{}")
	fmt.Fprintf(&buf, "\n}") // end if h.privateParams == nil
	fmt.Fprintf(&buf, "\nh.privateParams[name] = value")
	fmt.Fprintf(&buf, "\n}") // end switch name
	fmt.Fprintf(&buf, "\nreturn nil")
	fmt.Fprintf(&buf, "\n}") // end func (h *StandardHeaders) Set(name string, value interface{})

	fmt.Fprintf(&buf, "\n\n// PopulateMap populates a map with appropriate values that represent")
	fmt.Fprintf(&buf, "\n// the headers as a JSON object. This exists primarily because JWKs are")
	fmt.Fprintf(&buf, "\n// represented as flat objects instead of differentiating the different")
	fmt.Fprintf(&buf, "\n// parts of the message in separate sub objects.")
	fmt.Fprintf(&buf, "\nfunc (h StandardHeaders) PopulateMap(m map[string]interface{}) error {")
	fmt.Fprintf(&buf, "\nfor k, v := range h.privateParams {")
	fmt.Fprintf(&buf, "\nm[k] = v")
	fmt.Fprintf(&buf, "\n}") // end for k, v := range h.privateParams
	for _, f := range fields {
		fmt.Fprintf(&buf, "\nif v, ok := h.Get(%sKey); ok {", f.method)
		fmt.Fprintf(&buf, "\nm[%sKey] = v", f.method)
		fmt.Fprintf(&buf, "\n}") // end if v, ok := h.Get(%sKey); ok
	}
	fmt.Fprintf(&buf, "\n\nreturn nil")
	fmt.Fprintf(&buf, "\n}") // func (h StandardHeaders) PopulateMap(m map[string]interface{})

	fmt.Fprintf(&buf, "\n\n// ExtractMap populates the appropriate values from a map that represent")
	fmt.Fprintf(&buf, "\n// the headers as a JSON object. This exists primarily because JWKs are")
	fmt.Fprintf(&buf, "\n// represented as flat objects instead of differentiating the different")
	fmt.Fprintf(&buf, "\n// parts of the message in separate sub objects.")
	fmt.Fprintf(&buf, "\nfunc (h *StandardHeaders) ExtractMap(m map[string]interface{}) (err error) {")
	for _, f := range fields {
		fmt.Fprintf(&buf, "\nif v, ok := m[%sKey]; ok {", f.method)
		fmt.Fprintf(&buf, "\nif err := h.Set(%sKey, v); err != nil {", f.method)
		fmt.Fprintf(&buf, "\nreturn errors.Wrapf(err, `failed to set value for key %%s`, %sKey)", f.method)
		fmt.Fprintf(&buf, "\n}")
		fmt.Fprintf(&buf, "\ndelete(m, %sKey)", f.method)
		fmt.Fprintf(&buf, "\n}") // end if v, ok := m[%sKey]
	}
	fmt.Fprintf(&buf, "\n// Fix: A nil map is different from a empty map as far as deep.equal is concerned")
	fmt.Fprintf(&buf, "\nif len(m) > 0 {")
	fmt.Fprintf(&buf, "\nh.privateParams = m")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\n\nreturn nil")
	fmt.Fprintf(&buf, "\n}") // end func (h *StandardHeaders) ExtractMap(m map[string]interface{}) error

	fmt.Fprintf(&buf, "\n\nfunc (h StandardHeaders) Walk(f func(string, interface{}) error) error {")
	fmt.Fprintf(&buf, "\nfor _, key := range []string{")
	for i, field := range fields {
		fmt.Fprintf(&buf, "%sKey", field.method)
		if i < len(fields)-1 {
			fmt.Fprintf(&buf, ", ")
		}
	}
	fmt.Fprintf(&buf, "} {")
	fmt.Fprintf(&buf, "\nif v, ok := h.Get(key); ok {")
	fmt.Fprintf(&buf, "\nif err := f(key, v); err != nil {")
	fmt.Fprintf(&buf, "\nreturn errors.Wrapf(err, `walk function returned error for %%s`, key)")
	fmt.Fprintf(&buf, "\n}") // end if err := f(key, v); err != nil
	fmt.Fprintf(&buf, "\n}") // end if v, ok := h.Get(key); ok
	fmt.Fprintf(&buf, "\n}") // end for _, key := range []string{}

	fmt.Fprintf(&buf, "\n\nfor k, v := range h.privateParams {")
	fmt.Fprintf(&buf, "\nif err := f(k, v); err != nil {")
	fmt.Fprintf(&buf, "\nreturn errors.Wrapf(err, `walk function returned error for %%s`, k)")
	fmt.Fprintf(&buf, "\n}") // end if err := f(key, v); err != nil
	fmt.Fprintf(&buf, "\n}") // end for k, v := range h.privateParams
	fmt.Fprintf(&buf, "\nreturn nil")
	fmt.Fprintf(&buf, "\n}") // end func (h StandardHeaders) Walk(f func(string, interface{}) error)

	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		buf.WriteTo(os.Stdout)
		return errors.Wrap(err, `failed to format code`)
	}

	f, err := os.Create("headers_gen.go")
	if err != nil {
		return errors.Wrap(err, `failed to open headers_gen.go`)
	}
	defer f.Close()
	f.Write(formatted)

	return nil
}
