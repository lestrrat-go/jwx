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
	name      string
	method    string
	typ       string
	key       string
	comment   string
	hasAccept bool
	noDeref   bool
	jsonTag   string
}

func (f headerField) IsPointer() bool {
	return strings.HasPrefix(f.typ, "*")
}

func (f headerField) PointerElem() string {
	return strings.TrimPrefix(f.typ, "*")
}

var zerovals = map[string]string{
	"string":                 `""`,
	"jwa.SignatureAlgorithm": `""`,
	"[]string":               "0",
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
			name:      `JWSalgorithm`,
			method:    `Algorithm`,
			typ:       `jwa.SignatureAlgorithm`,
			key:       `alg`,
			comment:   `https://tools.ietf.org/html/rfc7515#section-4.1.1`,
			hasAccept: true,
			jsonTag:   "`" + `json:"alg,omitempty"` + "`",
		},
		{
			name:    `JWScontentType`,
			method:  `ContentType`,
			typ:     `string`,
			key:     `cty`,
			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.10`,
			jsonTag: "`" + `json:"cty,omitempty"` + "`",
		},
		{
			name:    `JWScritical`,
			method:  `Critical`,
			typ:     `[]string`,
			key:     `crit`,
			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.11`,
			jsonTag: "`" + `json:"crit,omitempty"` + "`",
		},
		{
			name:    `JWSjwk`,
			method:  `JWK`,
			typ:     `*jwk.Set`,
			key:     `jwk`,
			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.3`,
			jsonTag: "`" + `json:"jwk,omitempty"` + "`",
		},
		{
			name:    `JWSjwkSetURL`,
			method:  `JWKSetURL`,
			typ:     `string`,
			key:     `jku`,
			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.2`,
			jsonTag: "`" + `json:"jku,omitempty"` + "`",
		},
		{
			name:    `JWSkeyID`,
			method:  `KeyID`,
			typ:     `string`,
			key:     `kid`,
			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.4`,
			jsonTag: "`" + `json:"kid,omitempty"` + "`",
		},
		{
			name:    `JWStyp`,
			method:  `Type`,
			typ:     `string`,
			key:     `typ`,
			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.9`,
			jsonTag: "`" + `json:"typ,omitempty"` + "`",
		},
		{
			name:    `JWSx509CertChain`,
			method:  `X509CertChain`,
			typ:     `[]string`,
			key:     `x5c`,
			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.6`,
			jsonTag: "`" + `json:"x5c,omitempty"` + "`",
		},
		{
			name:    `JWSx509CertThumbprint`,
			method:  `X509CertThumbprint`,
			typ:     `string`,
			key:     `x5t`,
			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.7`,
			jsonTag: "`" + `json:"x5t,omitempty"` + "`",
		},
		{
			name:    `JWSx509CertThumbprintS256`,
			method:  `X509CertThumbprintS256`,
			typ:     `string`,
			key:     `x5t#S256`,
			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.8`,
			jsonTag: "`" + `json:"x5t#S256,omitempty"` + "`",
		},
		{
			name:    `JWSx509URL`,
			method:  `X509URL`,
			typ:     `string`,
			key:     `x5u`,
			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.5`,
			jsonTag: "`" + `json:"x5u,omitempty"` + "`",
		},
	}

	sort.Slice(fields, func(i, j int) bool {
		return fields[i].name < fields[j].name
	})

	var buf bytes.Buffer

	fmt.Fprintf(&buf, "\n// This file is auto-generated. DO NOT EDIT")
	fmt.Fprintf(&buf, "\npackage jws")
	fmt.Fprintf(&buf, "\n\nimport (")
	for _, pkg := range []string{"github.com/lestrrat-go/jwx/jwa", "github.com/lestrrat-go/jwx/jwk", "github.com/pkg/errors"} {
		fmt.Fprintf(&buf, "\n%s", strconv.Quote(pkg))
	}
	fmt.Fprintf(&buf, "\n)")

	fmt.Fprintf(&buf, "\n\nconst (")
	for _, f := range fields {
		fmt.Fprintf(&buf, "\n%sKey = %s", f.method, strconv.Quote(f.key))
	}
	fmt.Fprintf(&buf, "\n)") // end const

	fmt.Fprintf(&buf, "\n\ntype Headers interface {")
	fmt.Fprintf(&buf, "\nGet(string) (interface{}, bool)")
	fmt.Fprintf(&buf, "\nSet(string, interface{}) error")
	fmt.Fprintf(&buf, "\nAlgorithm() jwa.SignatureAlgorithm")

	/*	for _, f := range fields {
		fmt.Fprintf(&buf, "\n%s() %s", f.method, f.PointerElem())
	}*/
	fmt.Fprintf(&buf, "\n}") // end type Headers interface
	fmt.Fprintf(&buf, "\n\ntype StandardHeaders struct {")
	for _, f := range fields {
		fmt.Fprintf(&buf, "\n%s %s %s // %s", f.name, f.typ, f.jsonTag, f.comment)
	}
	fmt.Fprintf(&buf, "\nprivateParams map[string]interface{}")
	fmt.Fprintf(&buf, "\n}") // end type StandardHeaders

	fmt.Fprintf(&buf, "\n\nfunc (h *StandardHeaders) Algorithm() jwa.SignatureAlgorithm {")
	fmt.Fprintf(&buf, "\nreturn h.JWSalgorithm")
	fmt.Fprintf(&buf, "\n}") // func (h *StandardHeaders) %s() %s

	fmt.Fprintf(&buf, "\n\nfunc (h *StandardHeaders) Get(name string) (interface{}, bool) {")
	fmt.Fprintf(&buf, "\nswitch name {")
	for _, f := range fields {
		fmt.Fprintf(&buf, "\ncase %sKey:", f.method)
		fmt.Fprintf(&buf, "\nv := h.%s", f.name)

		if f.typ == "[]string" {
			fmt.Fprintf(&buf, "\nif len(v) == %s {", zeroval(f.typ))
		} else {
			fmt.Fprintf(&buf, "\nif v == %s {", zeroval(f.typ))
		}
		fmt.Fprintf(&buf, "\nreturn nil, false")
		fmt.Fprintf(&buf, "\n}") // end if h.%s == nil
		fmt.Fprintf(&buf, "\nreturn v, true")

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
		if f.hasAccept {
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
			if f.name == "JWSjwk" {
				fmt.Fprintf(&buf, "\nv, ok := value.(%s)", f.typ)
				fmt.Fprintf(&buf, "\nif ok {")
				fmt.Fprintf(&buf, "\nh.%s = v", f.name)
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

	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		buf.WriteTo(os.Stdout)
		return errors.Wrap(err, `failed to format code`)
	}

	f, err := os.Create("headers.go")
	if err != nil {
		return errors.Wrap(err, `failed to open headers.go`)
	}
	defer f.Close()
	f.Write(formatted)

	return nil
}
