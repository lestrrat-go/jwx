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
	name    string
	method  string
	typ     string
	key     string
	comment string
	hasAccept bool
}

func generateHeaders() error {
	zeroval := map[string]string{
		"string": `""`,
	}
	fields := []headerField{
		{
			name:    `algorithm`,
			method:  `Algorithm`,
			typ:     `jwa.SignatureAlgorithm`,
			key:     `alg`,
			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.1`,
			hasAccept: true,
		},
		{
			name:    `jwkSetURL`,
			method:  `JWKSetURL`,
			typ:     `string`,
			key:     `jku`,
			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.2`,
		},
		{
			name:    `jwk`,
			method:  `JWK`,
			typ:     `jwk.Key`,
			key:     `jwk`,
			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.3`,
		},
		{
			name:    `keyID`,
			method:  `KeyID`,
			typ:     `string`,
			key:     `kid`,
			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.4`,
		},
		{
			name:    `x509URL`,
			method:  `X509URL`,
			typ:     `string`,
			key:     `x5u`,
			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.5`,
		},
		{
			name:    `x509CertChain`,
			method:  `X509CertChain`,
			typ:     `[]string`,
			key:     `x5c`,
			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.6`,
		},
		{
			name:    `x509CertThumbprint`,
			method:  `x509CertThumbprint`,
			typ:     `string`,
			key:     `x5t`,
			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.7`,
		},
		{
			name:    `x509CertThumbprintS256`,
			method:  `x509CertThumbprintS256`,
			typ:     `string`,
			key:     `x5t#S256`,
			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.8`,
		},
		{
			name:    `typ`,
			method:  `Type`,
			typ:     `string`,
			key:     `typ`,
			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.9`,
		},
		{
			name:    `contentType`,
			method:  `ContentType`,
			typ:     `string`,
			key:     `cty`,
			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.10`,
		},
		{
			name:    `critical`,
			method:  `Critical`,
			typ:     `[]string`,
			key:     `crit`,
			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.11`,
		},
	}

	sort.Slice(fields, func(i, j int) bool {
		return fields[i].name < fields[j].name
	})

	var buf bytes.Buffer

	fmt.Fprintf(&buf, "\npackage jws")
	fmt.Fprintf(&buf, "\n\nimport (")
	for _, pkg := range []string{ "encoding/json", "github.com/lestrrat/go-jwx/jwa", "github.com/lestrrat/go-jwx/jwk", "github.com/pkg/errors"} {
		fmt.Fprintf(&buf, "\n%s", strconv.Quote(pkg))
	}
	fmt.Fprintf(&buf, "\n)")

	fmt.Fprintf(&buf, "\n\nconst (")
	for _, f := range fields {
		fmt.Fprintf(&buf, "\n%sKey = %s", f.method, strconv.Quote(f.key))
	}
	fmt.Fprintf(&buf, "\n)") // end const

	fmt.Fprintf(&buf, "\n\ntype StandardHeaders struct {")
	for _, f := range fields {
		fmt.Fprintf(&buf, "\n%s %s // %s", f.name, f.typ, f.comment)
	}
	fmt.Fprintf(&buf, "\nprivateParams map[string]interface{}")
	fmt.Fprintf(&buf, "\n}") // end type StandardHeaders

	fmt.Fprintf(&buf, "\n\nfunc (h *StandardHeaders) Set(name string, value interface{}) error {")
	fmt.Fprintf(&buf, "\nswitch name {")
	for _, f := range fields {
		fmt.Fprintf(&buf, "\ncase %sKey:", f.method)
		if f.hasAccept {
			fmt.Fprintf(&buf, "\nif err := h.%s.Accept(value); err != nil {", f.name)
			fmt.Fprintf(&buf, "\nreturn errors.Wrapf(err, `invalid value for %%s key`, %sKey)", f.method)
			fmt.Fprintf(&buf, "\n}") // end if err := h.%s.Accept(value)
			fmt.Fprintf(&buf, "\nreturn nil")
		} else {
			fmt.Fprintf(&buf, "\nif v, ok := value.(%s); ok {", f.typ)
			fmt.Fprintf(&buf, "\nh.%s = v", f.name)
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
	fmt.Fprintf(&buf, "\n\nfunc (h StandardHeaders) MarshalJSON() ([]byte, error) {")
	fmt.Fprintf(&buf, "\nm := map[string]interface{}{}")
	fmt.Fprintf(&buf, "\nfor k, v := range h.privateParams {")
	fmt.Fprintf(&buf, "\nm[k] = v")
	fmt.Fprintf(&buf, "\n}") // end for k, v := range h.privateParams
	for _, f := range fields {
		switch {
		case f.name == "algorithm":
			fmt.Fprintf(&buf, "\nm[%sKey] = h.%s", f.method, f.name)
		case strings.HasPrefix(f.typ, `[]`):
			fmt.Fprintf(&buf, "\n\nif len(h.%s) > 0 {", f.name)
			fmt.Fprintf(&buf, "\nm[%sKey] = h.%s", f.method, f.name)
			fmt.Fprintf(&buf, "\n}") // end if h.%s == %s
		default:
			zv, ok := zeroval[f.typ]
			if !ok {
				zv = "nil"
			}
			fmt.Fprintf(&buf, "\n\nif h.%s != %s {", f.name, zv)
			fmt.Fprintf(&buf, "\nm[%sKey] = h.%s", f.method, f.name)
			fmt.Fprintf(&buf, "\n}") // end if h.%s == %s
		}
	}
	fmt.Fprintf(&buf, "\n\nreturn json.Marshal(m)")
	fmt.Fprintf(&buf, "\n}") // end func (h StandardHeaders) MarshalJSON()

	fmt.Fprintf(&buf, "\n\nfunc (h *StandardHeaders) UnmarshalJSON(buf []byte) error {")
	fmt.Fprintf(&buf, "\nvar m map[string]interface{}")
	fmt.Fprintf(&buf, "\nif err := json.Unmarshal(buf, &m); err != nil {")
	fmt.Fprintf(&buf, "\nreturn errors.Wrap(err, `failed to unmarshal headers`)")
	fmt.Fprintf(&buf, "\n}") // end if err := json.Unmarshal(buf, &m)
	for _, f := range fields {
		fmt.Fprintf(&buf, "\nif v, ok := m[%sKey]; ok {", f.method)
		if f.hasAccept {
			fmt.Fprintf(&buf, "\nif err := h.%s.Accept(v); err != nil {", f.name)
			fmt.Fprintf(&buf, "\nreturn errors.Wrapf(err, `invalid value for key %%s: %%T`, %sKey, v)", f.method)
			fmt.Fprintf(&buf, "\n}") // end if err := h.%s.Accept(v)
		} else {
			fmt.Fprintf(&buf, "\nif x, ok := v.(%s); ok {", f.typ)
			fmt.Fprintf(&buf, "\nh.%s = x", f.name)
			fmt.Fprintf(&buf, "\ndelete(m, %sKey)", f.method)
			fmt.Fprintf(&buf, "\n} else {") // if x, ok := v.(%s)
			fmt.Fprintf(&buf, "\nreturn errors.Errorf(`invalid value for key %%s: %%T`, %sKey, v)", f.method)
			fmt.Fprintf(&buf, "\n}")
		}
		fmt.Fprintf(&buf, "\n}") // end if v, ok := m[%sKey]
	}
	fmt.Fprintf(&buf, "\nh.privateParams = m")
	fmt.Fprintf(&buf, "\nreturn nil")
	fmt.Fprintf(&buf, "\n}") // end func (h *StandardHeaders) UnmarshalJSON(buf []byte) error

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
