package main

// This program generates all of the possible key types that we use
// RSA public/private keys, ECDSA private/public keys, and symmetric keys
//
// Each share the same standard header section, but have their own
// header fields

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/tools/imports"
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

func _main() error {
	if err := generateGenericHeaders(); err != nil {
		return err
	}

	if err := generateHeaders(); err != nil {
		return err
	}

	return nil
}

type headerField struct {
	name       string
	method     string
	typ        string
	returnType string
	key        string
	jsonTag    string
	comment    string
	hasAccept  bool
	hasGet     bool
	noDeref    bool
	isList     bool
	isStd      bool
	optional   bool
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

func (f headerField) Tag() string {
	if f.jsonTag != "" {
		return f.jsonTag
	}

	return "`json:\"" + f.key + ",omitempty\"`"
}

var zerovals = map[string]string{
	"string":                     `""`,
	"jwa.EllipticCurveAlgorithm": `jwa.InvalidEllipticCurve`,
	"jwa.SignatureAlgorithm":     `""`,
	"jwa.KeyType":                "jwa.InvalidKeyType",
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
	return !(strings.HasPrefix(s, `*`) || strings.HasPrefix(s, `[]`) || strings.HasSuffix(s, `List`))
}

var standardHeaders []headerField

func init() {
	standardHeaders = []headerField{
		{
			name:      `keyType`,
			method:    `KeyType`,
			typ:       `jwa.KeyType`,
			key:       `kty`,
			comment:   `https://tools.ietf.org/html/rfc7517#section-4.1`,
			hasAccept: true,
		},
		{
			name:    `keyUsage`,
			method:  `KeyUsage`,
			key:     `use`,
			typ:     `string`,
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
			typ:     `string`,
			key:     `alg`,
			comment: `https://tools.ietf.org/html/rfc7517#section-4.4`,
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
			name:       `x509CertChain`,
			method:     `X509CertChain`,
			typ:        `CertificateChain`,
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
			typ:     `string`,
			key:     `x5t`,
			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.7`,
		},
		{
			name:    `x509CertThumbprintS256`,
			method:  `X509CertThumbprintS256`,
			typ:     `string`,
			key:     `x5t#S256`,
			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.8`,
		},
	}

	for i := 0; i < len(standardHeaders); i++ {
		standardHeaders[i].isStd = true
	}
}

type keyType struct {
	filename    string
	prefix      string
	headerTypes []headerType
	defaultKty  string
}

type headerType struct {
	allHeaders []headerField
	headers    []headerField
	name       string
	structName string
}

var keyTypes = []keyType{
	{
		filename:   `rsa_gen.go`,
		prefix:     `rsa`, // todo: really use this?
		defaultKty: `jwa.RSA`,
		headerTypes: []headerType{
			{
				name: `PublicKey`,
				headers: []headerField{
					{
						name:   `n`,
						method: `N`,
						typ:    `[]byte`,
						key:    `n`,
					},
					{
						name:   `e`,
						method: `E`,
						typ:    `[]byte`,
						key:    `e`,
					},
				},
			},
			{
				name: `PrivateKey`,
				headers: []headerField{
					{
						name:   `d`,
						method: `D`,
						typ:    `[]byte`,
						key:    `d`,
					},
					{
						name:   `p`,
						method: `P`,
						typ:    `[]byte`,
						key:    `p`,
					},
					{
						name:   `q`,
						method: `Q`,
						typ:    `[]byte`,
						key:    `q`,
					},
					{
						name:     `dp`,
						method:   `DP`,
						typ:      `[]byte`,
						key:      `dp`,
						optional: true,
					},
					{
						name:     `dq`,
						method:   `DQ`,
						typ:      `[]byte`,
						key:      `dq`,
						optional: true,
					},
					{
						name:     `qi`,
						method:   `QI`,
						typ:      `[]byte`,
						key:      `qi`,
						optional: true,
					},
					{
						name:   `n`,
						method: `N`,
						typ:    `[]byte`,
						key:    `n`,
					},
					{
						name:   `e`,
						method: `E`,
						typ:    `[]byte`,
						key:    `e`,
					},
				},
			},
		},
	},
	{
		filename:   `ecdsa_gen.go`,
		prefix:     `ecdsa`,
		defaultKty: `jwa.EC`,
		headerTypes: []headerType{
			{
				name: `PublicKey`,
				headers: []headerField{
					{
						name:   `x`,
						method: `X`,
						typ:    `[]byte`,
						key:    `x`,
					},
					{
						name:   `y`,
						method: `Y`,
						typ:    `[]byte`,
						key:    `y`,
					},
					{
						name:   `crv`,
						method: `Crv`,
						typ:    `jwa.EllipticCurveAlgorithm`,
						key:    `crv`,
					},
				},
			},
			{
				name: `PrivateKey`,
				headers: []headerField{
					{
						name:   `d`,
						method: `D`,
						typ:    `[]byte`,
						key:    `d`,
					},
					{
						name:   `x`,
						method: `X`,
						typ:    `[]byte`,
						key:    `x`,
					},
					{
						name:   `y`,
						method: `Y`,
						typ:    `[]byte`,
						key:    `y`,
					},
					{
						name:   `crv`,
						method: `Crv`,
						typ:    `jwa.EllipticCurveAlgorithm`,
						key:    `crv`,
					},
				},
			},
		},
	},
	{
		filename:   `symmetric_gen.go`,
		prefix:     `symmetric`,
		defaultKty: `jwa.OctetSeq`,
		headerTypes: []headerType{
			{
				name:       "SymmetricKey",
				structName: `SymmetricKey`,
				headers: []headerField{
					{
						name:   `octets`,
						method: `Octets`,
						typ:    `[]byte`,
						key:    `k`,
					},
				},
			},
		},
	},
}

func generateGenericHeaders() error {
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
	for _, f := range standardHeaders {
		fmt.Fprintf(&buf, "\n%sKey = %s", f.method, strconv.Quote(f.key))
	}
	fmt.Fprintf(&buf, "\n)") // end const

	fmt.Fprintf(&buf, "\n\ntype Headers interface {")
	fmt.Fprintf(&buf, "\nGet(string) (interface{}, bool)")
	fmt.Fprintf(&buf, "\nSet(string, interface{}) error")
	fmt.Fprintf(&buf, "\nIterate(ctx context.Context) HeaderIterator")
	fmt.Fprintf(&buf, "\nWalk(context.Context, HeaderVisitor) error")
	fmt.Fprintf(&buf, "\nAsMap(context.Context) (map[string]interface{}, error)")
	for _, f := range standardHeaders {
		fmt.Fprintf(&buf, "\n%s() ", f.method)
		if f.returnType != "" {
			fmt.Fprintf(&buf, "%s", f.returnType)
		} else if f.IsPointer() && f.noDeref {
			fmt.Fprintf(&buf, "%s", f.typ)
		} else {
			fmt.Fprintf(&buf, "%s", f.PointerElem())
		}
	}
	fmt.Fprintf(&buf, "\n}")

	return writeFormattedCodeToFile("headers_gen.go", &buf)
}

func generateHeaders() error {
	for _, keyType := range keyTypes {
		if err := generateHeader(keyType); err != nil {
			return errors.Wrapf(err, `failed to generate headers for %s`, keyType.filename)
		}
	}
	return nil
}

func generateHeader(kt keyType) error {
	sort.Slice(kt.headerTypes, func(i, j int) bool {
		return kt.headerTypes[i].name < kt.headerTypes[j].name
	})

	var buf bytes.Buffer

	fmt.Fprintf(&buf, "\n// This file is auto-generated. DO NOT EDIT")
	fmt.Fprintf(&buf, "\n\npackage jwk")
	fmt.Fprintf(&buf, "\n\nimport (")
	for _, pkg := range []string{"crypto/x509", "fmt"} {
		fmt.Fprintf(&buf, "\n%s", strconv.Quote(pkg))
	}
	fmt.Fprintf(&buf, "\n\n")
	for _, pkg := range []string{"github.com/lestrrat-go/jwx/internal/base64", "github.com/lestrrat-go/jwx/jwa", "github.com/pkg/errors"} {
		fmt.Fprintf(&buf, "\n%s", strconv.Quote(pkg))
	}
	fmt.Fprintf(&buf, "\n)")

	// Find the unique set of headers so we don't redeclare them
	var constants []headerField
	var seenHeaders = make(map[string]struct{})

	for _, ht := range kt.headerTypes {
		for _, f := range ht.headers {
			if _, ok := seenHeaders[f.key]; ok {
				continue
			}
			constants = append(constants, f)
			seenHeaders[f.key] = struct{}{}
		}
	}
	sort.Slice(constants, func(i, j int) bool {
		return constants[i].key < constants[j].key
	})

	fmt.Fprintf(&buf, "\n\nconst (")
	for _, f := range constants {
		fmt.Fprintf(&buf, "\n%s%sKey = %s", kt.prefix, f.method, strconv.Quote(f.key))
	}
	fmt.Fprintf(&buf, "\n)") // end const

	for i := 0 ; i < len(kt.headerTypes); i++ {
		ht := kt.headerTypes[i]
		ht.allHeaders = append(standardHeaders, ht.headers...)
		sort.Slice(ht.headers, func(i, j int) bool {
			return ht.headers[i].name < ht.headers[j].name
		})

		sort.Slice(ht.allHeaders, func(i, j int) bool {
			return ht.allHeaders[i].name < ht.allHeaders[j].name
		})

		structName := ht.structName
		if len(structName) == 0 {
			structName = strings.ToUpper(kt.prefix) + ht.name
		}

		fmt.Fprintf(&buf, "\n\ntype %s struct {", structName)
		for _, header := range ht.allHeaders {
			fmt.Fprintf(&buf, "\n%s %s", header.name, fieldStorageType(header.typ))
			if len(header.comment) > 0 {
				fmt.Fprintf(&buf, " // %s", header.comment)
			}
		}
		fmt.Fprintf(&buf, "\nprivateParams map[string]interface{}")
		fmt.Fprintf(&buf, "\n}")

		// Proxy is used when unmarshaling headers
		fmt.Fprintf(&buf, "\n\ntype %s%sMarshalProxy struct {", kt.prefix, ht.name)
		for _, f := range ht.allHeaders {
			switch f.typ {
			case byteSliceType:
				// XXX encoding/json uses base64.StdEncoding, which require padding
				// but we may or may not be dealing with padded base64's.
				// In order to let the proxy handle this correctly, we need to
				// accept the values in JSON as strings, not []bytes
				fmt.Fprintf(&buf, "\nX%s *string %s", f.name, f.Tag())
			default:
				fmt.Fprintf(&buf, "\nX%s %s %s", f.name, fieldStorageType(f.typ), f.Tag())
			}
		}
		fmt.Fprintf(&buf, "\n}")

		for _, f := range ht.allHeaders {
			fmt.Fprintf(&buf, "\n\nfunc (h *%s) %s() ", structName, f.method)
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
				fmt.Fprintf(&buf, "\nreturn %s", zeroval(f.PointerElem()))
			} else if !f.IsPointer() {
				if fieldStorageTypeIsIndirect(f.typ) {
					fmt.Fprintf(&buf, "\nif h.%s != nil {", f.name)
					fmt.Fprintf(&buf, "\nreturn *(h.%s)", f.name)
					fmt.Fprintf(&buf, "\n}")
					fmt.Fprintf(&buf, "\nreturn %s", zeroval(f.PointerElem()))
				} else {
					fmt.Fprintf(&buf, "\nreturn h.%s", f.name)
				}
			}
			fmt.Fprintf(&buf, "\n}") // func (h *stdHeaders) %s() %s
		}

		// Generate a function that iterates through all of the keys
		// in this header.
		fmt.Fprintf(&buf, "\n\nfunc (h *%s) iterate(ctx context.Context, ch chan *HeaderPair) {", structName)
		fmt.Fprintf(&buf, "\ndefer close(ch)")

		// NOTE: building up an array is *slow*?
		fmt.Fprintf(&buf, "\nvar pairs []*HeaderPair")
		for _, f := range ht.allHeaders {
			var keyName string
			if f.isStd {
				keyName = f.method + "Key"
			} else {
				keyName = kt.prefix + f.method + "Key"
			}
			fmt.Fprintf(&buf, "\nif h.%s != nil {", f.name)
			if fieldStorageTypeIsIndirect(f.typ) {
				fmt.Fprintf(&buf, "\npairs = append(pairs, &HeaderPair{Key: %s, Value: *(h.%s)})", keyName, f.name)
			} else {
				fmt.Fprintf(&buf, "\npairs = append(pairs, &HeaderPair{Key: %s, Value: h.%s})", keyName, f.name)
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

		fmt.Fprintf(&buf, "\n\nfunc (h *%s) PrivateParams() map[string]interface{} {", structName)
		fmt.Fprintf(&buf, "\nreturn h.privateParams")
		fmt.Fprintf(&buf, "\n}")

		fmt.Fprintf(&buf, "\n\nfunc (h *%s) Get(name string) (interface{}, bool) {", structName)
		fmt.Fprintf(&buf, "\nswitch name {")
		for _, f := range ht.allHeaders {
			if f.isStd {
				fmt.Fprintf(&buf, "\ncase %sKey:", f.method)
			} else {
				fmt.Fprintf(&buf, "\ncase %s%sKey:", kt.prefix, f.method)
			}
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
		fmt.Fprintf(&buf, "\n}") // func (h *%s) Get(name string) (interface{}, bool)

		fmt.Fprintf(&buf, "\n\nfunc (h *%s) Set(name string, value interface{}) error {", structName)
		fmt.Fprintf(&buf, "\nswitch name {")
		for _, f := range ht.allHeaders {
			var keyName string
			if f.isStd {
				keyName = f.method + "Key"
			} else {
				keyName = kt.prefix + f.method + "Key"
			}
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
				fmt.Fprintf(&buf, "\nvar acceptor %s", f.typ)
				fmt.Fprintf(&buf, "\nif err := acceptor.Accept(value); err != nil {")
				fmt.Fprintf(&buf, "\nreturn errors.Wrapf(err, `invalid value for %%s key`, %s)", keyName)
				fmt.Fprintf(&buf, "\n}") // end if err := h.%s.Accept(value)
				if fieldStorageTypeIsIndirect(f.typ) {
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
		fmt.Fprintf(&buf, "\nif h.privateParams == nil {")
		fmt.Fprintf(&buf, "\nh.privateParams = map[string]interface{}{}")
		fmt.Fprintf(&buf, "\n}") // end if h.privateParams == nil
		fmt.Fprintf(&buf, "\nh.privateParams[name] = value")
		fmt.Fprintf(&buf, "\n}") // end switch name
		fmt.Fprintf(&buf, "\nreturn nil")
		fmt.Fprintf(&buf, "\n}") // end func (h *%s) Set(name string, value interface{})

		fmt.Fprintf(&buf, "\n\nfunc (h *%s) UnmarshalJSON(buf []byte) error {", structName)
		fmt.Fprintf(&buf, "\nvar proxy %s%sMarshalProxy", kt.prefix, ht.name)
		fmt.Fprintf(&buf, "\nif err := json.Unmarshal(buf, &proxy); err != nil {")
		fmt.Fprintf(&buf, "\nreturn errors.Wrap(err, `failed to unmarshal %s`)", structName)
		fmt.Fprintf(&buf, "\n}")

		for _, f := range ht.allHeaders {
			switch f.typ {
			case byteSliceType:
				// XXX encoding/json uses base64.StdEncoding, which require padding
				// but we may or may not be dealing with padded base64's.
				// The unmarshal proxy takes this into account, and grabs the value
				// as strings so that we can do our own decoding magic
				if !f.optional {
					fmt.Fprintf(&buf, "\nif proxy.X%[1]s == nil {", f.name)
					fmt.Fprintf(&buf, "\nreturn errors.New(`required field %s is missing`)", f.key)
					fmt.Fprintf(&buf, "\n}")
				}

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
		for _, f := range ht.allHeaders {
			var keyName string
			if f.isStd {
				keyName = f.method + "Key"
			} else {
				keyName = kt.prefix + f.method + "Key"
			}
			fmt.Fprintf(&buf, "\ndelete(m, %s)", keyName)
		}

		fmt.Fprintf(&buf, "\nh.privateParams = m")
		fmt.Fprintf(&buf, "\nreturn nil")
		fmt.Fprintf(&buf, "\n}")

		fmt.Fprintf(&buf, "\n\nfunc (h %s) MarshalJSON() ([]byte, error) {", structName)
		fmt.Fprintf(&buf, "\nvar proxy %s%sMarshalProxy", kt.prefix, ht.name)
		for _, f := range ht.allHeaders {
			switch f.typ {
			case byteSliceType:
				// XXX encoding/json uses base64.StdEncoding, which require padding
				// but we may or may not be dealing with padded base64's.
				// Before marshaling this value to JSON, we must first encode it
				fmt.Fprintf(&buf, "\nif len(h.%s) > 0 {", f.name)
				fmt.Fprintf(&buf, "\nv := base64.EncodeToStringStd(h.%s)", f.name)
				fmt.Fprintf(&buf, "\nproxy.X%s = &v", f.name)
				fmt.Fprintf(&buf, "\n}")
			default:
				fmt.Fprintf(&buf, "\nproxy.X%[1]s = h.%[1]s", f.name)
				if f.key == "kty" {
					fmt.Fprintf(&buf, "\nif proxy.X%s == nil {", f.name)
					fmt.Fprintf(&buf, "\nv := %s", kt.defaultKty)
					fmt.Fprintf(&buf, "\nproxy.X%s = &v", f.name)
					fmt.Fprintf(&buf, "\n}")
				}
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

		fmt.Fprintf(&buf, "\n\nfunc (h *%s) Iterate(ctx context.Context) HeaderIterator {", structName)
		fmt.Fprintf(&buf, "\nch := make(chan *HeaderPair)")
		fmt.Fprintf(&buf, "\ngo h.iterate(ctx, ch)")
		fmt.Fprintf(&buf, "\nreturn mapiter.New(ch)")
		fmt.Fprintf(&buf, "\n}")

		fmt.Fprintf(&buf, "\n\nfunc (h *%s) Walk(ctx context.Context, visitor HeaderVisitor) error {", structName)
		fmt.Fprintf(&buf, "\nreturn iter.WalkMap(ctx, h, visitor)")
		fmt.Fprintf(&buf, "\n}")

		fmt.Fprintf(&buf, "\n\nfunc (h *%s) AsMap(ctx context.Context) (map[string]interface{}, error) {", structName)
		fmt.Fprintf(&buf, "\nreturn iter.AsMap(ctx, h)")
		fmt.Fprintf(&buf, "\n}")
	}

	return writeFormattedCodeToFile(kt.filename, &buf)
}

func writeFormattedCodeToFile(filename string, src io.Reader) error {
	buf, err := ioutil.ReadAll(src)
	if err != nil {
		return errors.Wrap(err, `failed to read from source`)
	}

	formatted, err := imports.Process("", buf, nil)
	if err != nil {
		scanner := bufio.NewScanner(bytes.NewReader(buf))
		lineno := 1
		for scanner.Scan() {
			txt := scanner.Text()
			fmt.Fprintf(os.Stdout, "%03d: %s\n", lineno, txt)
			lineno++
		}
		return errors.Wrap(err, `failed to format code`)
	}

	f, err := os.Create(filename)
	if err != nil {
		return errors.Wrapf(err, `failed to open %s.go`, filename)
	}
	defer f.Close()
	f.Write(formatted)

	return nil
}
