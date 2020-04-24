package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/tools/imports"
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

func fieldStorageType(s string) string {
	if fieldStorageTypeIsIndirect(s) {
		return `*` + s
	}
	return s
}

func fieldStorageTypeIsIndirect(s string) bool {
	return !(s == "jwk.Key" || strings.HasPrefix(s, `*`) || strings.HasPrefix(s, `[]`))
}

func generateHeaders() error {
	const jwkKey = "jwk"

	fields := []headerField{
		{
			name:      `algorithm`,
			method:    `Algorithm`,
			typ:       `jwa.SignatureAlgorithm`,
			key:       `alg`,
			comment:   `https://tools.ietf.org/html/rfc7515#section-4.1.1`,
			hasAccept: true,
			jsonTag:   "`" + `json:"alg,omitempty"` + "`",
		},
		{
			name:    `contentType`,
			method:  `ContentType`,
			typ:     `string`,
			key:     `cty`,
			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.10`,
			jsonTag: "`" + `json:"cty,omitempty"` + "`",
		},
		{
			name:    `critical`,
			method:  `Critical`,
			typ:     `[]string`,
			key:     `crit`,
			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.11`,
			jsonTag: "`" + `json:"crit,omitempty"` + "`",
		},
		{
			name:    `jwk`,
			method:  `JWK`,
			typ:     `jwk.Key`,
			key:     `jwk`,
			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.3`,
			jsonTag: "`" + `json:"jwk,omitempty"` + "`",
		},
		{
			name:    `jwkSetURL`,
			method:  `JWKSetURL`,
			typ:     `string`,
			key:     `jku`,
			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.2`,
			jsonTag: "`" + `json:"jku,omitempty"` + "`",
		},
		{
			name:    `keyID`,
			method:  `KeyID`,
			typ:     `string`,
			key:     `kid`,
			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.4`,
			jsonTag: "`" + `json:"kid,omitempty"` + "`",
		},
		{
			name:    `typ`,
			method:  `Type`,
			typ:     `string`,
			key:     `typ`,
			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.9`,
			jsonTag: "`" + `json:"typ,omitempty"` + "`",
		},
		{
			name:    `x509CertChain`,
			method:  `X509CertChain`,
			typ:     `[]string`,
			key:     `x5c`,
			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.6`,
			jsonTag: "`" + `json:"x5c,omitempty"` + "`",
		},
		{
			name:    `x509CertThumbprint`,
			method:  `X509CertThumbprint`,
			typ:     `string`,
			key:     `x5t`,
			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.7`,
			jsonTag: "`" + `json:"x5t,omitempty"` + "`",
		},
		{
			name:    `x509CertThumbprintS256`,
			method:  `X509CertThumbprintS256`,
			typ:     `string`,
			key:     `x5t#S256`,
			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.8`,
			jsonTag: "`" + `json:"x5t#S256,omitempty"` + "`",
		},
		{
			name:    `x509URL`,
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
	pkgs := []string{
		"bytes",
		"context",
		"encoding/json",
		"fmt",
		"sort",
		"strconv",
		"github.com/lestrrat-go/jwx/jwa",
		"github.com/lestrrat-go/jwx/jwk",
		"github.com/pkg/errors",
	}
	for _, pkg := range pkgs {
		fmt.Fprintf(&buf, "\n%s", strconv.Quote(pkg))
	}
	fmt.Fprintf(&buf, "\n)")

	fmt.Fprintf(&buf, "\n\nconst (")
	for _, f := range fields {
		fmt.Fprintf(&buf, "\n%sKey = %s", f.method, strconv.Quote(f.key))
	}
	fmt.Fprintf(&buf, "\n)") // end const

	fmt.Fprintf(&buf, "\n\n// Headers describe a standard Header set.")
	fmt.Fprintf(&buf, "\ntype Headers interface {")
	// These are the basic values that most jws have
	for _, f := range fields {
		fmt.Fprintf(&buf, "\n%s() %s", f.method, f.PointerElem())
	}

	// These are used to iterate through all keys in a header
	fmt.Fprintf(&buf, "\nIterate(ctx context.Context) Iterator")
	fmt.Fprintf(&buf, "\nWalk(ctx context.Context, v Visitor) error")
	fmt.Fprintf(&buf, "\nAsMap(ctx context.Context) (map[string]interface{}, error)")

	// These are used to access a single element by key name
	fmt.Fprintf(&buf, "\nGet(string) (interface{}, bool)")
	fmt.Fprintf(&buf, "\nSet(string, interface{}) error")

	fmt.Fprintf(&buf, "\n}")

	fmt.Fprintf(&buf, "\n\ntype stdHeaders struct {")
	for _, f := range fields {
		fmt.Fprintf(&buf, "\n%s %s %s // %s", f.name, fieldStorageType(f.typ), f.jsonTag, f.comment)
	}
	fmt.Fprintf(&buf, "\nprivateParams map[string]interface{}")
	fmt.Fprintf(&buf, "\n}") // end type StandardHeaders

	// Proxy is used when unmarshaling headers
	fmt.Fprintf(&buf, "\n\ntype standardHeadersMarshalProxy struct {")
	for _, f := range fields {
		if f.name == jwkKey {
			fmt.Fprintf(&buf, "\nX%s json.RawMessage %s", f.name, f.jsonTag)
		} else {
			fmt.Fprintf(&buf, "\nX%s %s %s", f.name, fieldStorageType(f.typ), f.jsonTag)
		}
	}
	fmt.Fprintf(&buf, "\n}") // end type StandardHeaders

	fmt.Fprintf(&buf, "\n\nfunc NewHeaders() Headers {")
	fmt.Fprintf(&buf, "\nreturn &stdHeaders{}")
	fmt.Fprintf(&buf, "\n}")

	for _, f := range fields {
		fmt.Fprintf(&buf, "\n\nfunc (h *stdHeaders) %s() %s{", f.method, f.typ)
		if fieldStorageTypeIsIndirect(f.typ) {
			fmt.Fprintf(&buf, "\nif h.%s == nil {", f.name)
			fmt.Fprintf(&buf, "\nreturn %s", zeroval(f.typ))
			fmt.Fprintf(&buf, "\n}")
			fmt.Fprintf(&buf, "\nreturn *(h.%s)", f.name)
		} else {
			fmt.Fprintf(&buf, "\nreturn h.%s", f.name)
		}
		fmt.Fprintf(&buf, "\n}") // func (h *stdHeaders) %s() %s
	}

	// Generate a function that iterates through all of the keys
	// in this header.
	fmt.Fprintf(&buf, "\n\nfunc (h *stdHeaders) iterate(ctx context.Context, ch chan *HeaderPair) {")
	fmt.Fprintf(&buf, "\ndefer close(ch)")

	// NOTE: building up an array is *slow*?
	fmt.Fprintf(&buf, "\nvar pairs []*HeaderPair")
	for _, f := range fields {
		fmt.Fprintf(&buf, "\nif h.%s != nil {", f.name)
		if fieldStorageTypeIsIndirect(f.typ) {
			fmt.Fprintf(&buf, "\npairs = append(pairs, &HeaderPair{Key: %sKey, Value: *(h.%s)})", f.method, f.name)
		} else {
			fmt.Fprintf(&buf, "\npairs = append(pairs, &HeaderPair{Key: %sKey, Value: h.%s})", f.method, f.name)
		}
		fmt.Fprintf(&buf, "\n}")
	}
	fmt.Fprintf(&buf, "\nfor k, v := range h.privateParams {")
	fmt.Fprintf(&buf, "\npairs = append(pairs, &HeaderPair{Key: k, Value: v})")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\nfor _, pair := range pairs {")
	fmt.Fprintf(&buf, "\nselect {")
	fmt.Fprintf(&buf, "\ncase <-ctx.Done():")
	fmt.Fprintf(&buf, "\nreturn")
	fmt.Fprintf(&buf, "\ncase ch<-pair:")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\n}") // end of (h *stdHeaders) iterate(...)

	fmt.Fprintf(&buf, "\n\nfunc (h *stdHeaders) PrivateParams() map[string]interface{} {")
	fmt.Fprintf(&buf, "\nreturn h.privateParams")
	fmt.Fprintf(&buf, "\n}")

	fmt.Fprintf(&buf, "\n\nfunc (h *stdHeaders) Get(name string) (interface{}, bool) {")
	fmt.Fprintf(&buf, "\nswitch name {")
	for _, f := range fields {
		fmt.Fprintf(&buf, "\ncase %sKey:", f.method)
		fmt.Fprintf(&buf, "\nif h.%s == nil {", f.name)
		fmt.Fprintf(&buf, "\nreturn nil, false")
		fmt.Fprintf(&buf, "\n}")
		if fieldStorageTypeIsIndirect(f.typ) {
			fmt.Fprintf(&buf, "\nreturn *(h.%s), true", f.name)
		} else {
			fmt.Fprintf(&buf, "\nreturn h.%s, true", f.name)
		}
	}
	fmt.Fprintf(&buf, "\ndefault:")
	fmt.Fprintf(&buf, "\nv, ok := h.privateParams[name]")
	fmt.Fprintf(&buf, "\nreturn v, ok")
	fmt.Fprintf(&buf, "\n}") // end switch name
	fmt.Fprintf(&buf, "\n}") // func (h *stdHeaders) Get(name string) (interface{}, bool)

	fmt.Fprintf(&buf, "\n\nfunc (h *stdHeaders) Set(name string, value interface{}) error {")
	fmt.Fprintf(&buf, "\nswitch name {")
	for _, f := range fields {
		fmt.Fprintf(&buf, "\ncase %sKey:", f.method)
		if f.hasAccept {
			fmt.Fprintf(&buf, "\nvar acceptor %s", f.PointerElem())
			fmt.Fprintf(&buf, "\nif err := acceptor.Accept(value); err != nil {")
			fmt.Fprintf(&buf, "\nreturn errors.Wrapf(err, `invalid value for %%s key`, %sKey)", f.method)
			fmt.Fprintf(&buf, "\n}") // end if err := h.%s.Accept(value)
			fmt.Fprintf(&buf, "\nh.%s = &acceptor", f.name)
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
	fmt.Fprintf(&buf, "\n}") // end func (h *stdHeaders) Set(name string, value interface{})

	fmt.Fprintf(&buf, "\n\nfunc (h *stdHeaders) UnmarshalJSON(buf []byte) error {")
	fmt.Fprintf(&buf, "\nvar proxy standardHeadersMarshalProxy")
	fmt.Fprintf(&buf, "\nif err := json.Unmarshal(buf, &proxy); err != nil {")
	fmt.Fprintf(&buf, "\nreturn errors.Wrap(err, `failed to unmarshal headers`)")
	fmt.Fprintf(&buf, "\n}")

	// Copy every field except for jwk, whose type needs to be guessed
	fmt.Fprintf(&buf, "\n\nh.jwk = nil")
	fmt.Fprintf(&buf, "\nif jwkField := proxy.Xjwk; len(jwkField) > 0 {")
	fmt.Fprintf(&buf, "\nset, err := jwk.ParseBytes([]byte(proxy.Xjwk))")
	fmt.Fprintf(&buf, "\n if err != nil {")
	fmt.Fprintf(&buf, "\nreturn errors.Wrap(err, `failed to parse jwk field`)")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\nh.jwk = set.Keys[0]")
	fmt.Fprintf(&buf, "\n}")

	for _, f := range fields {
		if f.name == jwkKey {
			continue
		}

		fmt.Fprintf(&buf, "\nh.%[1]s = proxy.X%[1]s", f.name)
	}

	// Now for the fun part... It's quite silly, but we need to check if we
	// have other parameters.
	fmt.Fprintf(&buf, "\nvar m map[string]interface{}")
	fmt.Fprintf(&buf, "\nif err := json.Unmarshal(buf, &m); err != nil {")
	fmt.Fprintf(&buf, "\nreturn errors.Wrap(err, `failed to parse privsate parameters`)")
	fmt.Fprintf(&buf, "\n}")
	// Delete all known keys
	for _, f := range fields {
		fmt.Fprintf(&buf, "\ndelete(m, %sKey)", f.method)
	}

	fmt.Fprintf(&buf, "\nh.privateParams = m")
	fmt.Fprintf(&buf, "\nreturn nil")
	fmt.Fprintf(&buf, "\n}")

	fmt.Fprintf(&buf, "\n\nfunc (h stdHeaders) MarshalJSON() ([]byte, error) {")
	fmt.Fprintf(&buf, "\nvar proxy standardHeadersMarshalProxy")
	fmt.Fprintf(&buf, "\nif h.jwk != nil {")
	fmt.Fprintf(&buf, "\njwkbuf, err := json.Marshal(h.jwk)")
	fmt.Fprintf(&buf, "\nif err != nil {")
	fmt.Fprintf(&buf, "\nreturn nil, errors.Wrap(err, `failed to marshal jwk field`)")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\nproxy.Xjwk = jwkbuf")
	fmt.Fprintf(&buf, "\n}")

	for _, f := range fields {
		if f.name != jwkKey {
			fmt.Fprintf(&buf, "\nproxy.X%[1]s = h.%[1]s", f.name)
		}
	}

	fmt.Fprintf(&buf, "\nvar buf bytes.Buffer")
	fmt.Fprintf(&buf, "\nenc := json.NewEncoder(&buf)")
	fmt.Fprintf(&buf, "\nif err := enc.Encode(proxy); err != nil {")
	fmt.Fprintf(&buf, "\nreturn nil, errors.Wrap(err, `failed to encode proxy to JSON`)")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\nhasContent := buf.Len() > 3 // encoding/json always adds a newline, so \"{}\\n\" is the empty hash")
	fmt.Fprintf(&buf, "\nif l := len(h.privateParams); l> 0 {")
	fmt.Fprintf(&buf, "\nbuf.Truncate(buf.Len()-2)")
	fmt.Fprintf(&buf, "\nkeys := make([]string, 0, l)")
	fmt.Fprintf(&buf, "\nfor k := range h.privateParams {")
	fmt.Fprintf(&buf, "\nkeys = append(keys, k)")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\nsort.Strings(keys)")
	fmt.Fprintf(&buf, "\nfor i, k := range keys {")
	fmt.Fprintf(&buf, "\nif hasContent || i > 0 {")
	fmt.Fprintf(&buf, "\nfmt.Fprintf(&buf, `,`)")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\nfmt.Fprintf(&buf, `%%s:`, strconv.Quote(k))")
	fmt.Fprintf(&buf, "\nif err := enc.Encode(h.privateParams[k]); err != nil {")
	fmt.Fprintf(&buf, "\nreturn nil, errors.Wrapf(err, `failed to encode private param %%s`, k)")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\nfmt.Fprintf(&buf, `}`)")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\nreturn buf.Bytes(), nil")
	fmt.Fprintf(&buf, "\n}") // end of MarshalJSON

	formatted, err := imports.Process("", buf.Bytes(), nil)
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
