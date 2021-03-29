package main

// This program generates all of the possible key types that we use
// RSA public/private keys, ECDSA private/public keys, and symmetric keys
//
// Each share the same standard header section, but have their own
// header fields

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/lestrrat-go/codegen"
	"github.com/pkg/errors"
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

	//nolint:revive
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
	return s == "KeyOperationList" || !(strings.HasPrefix(s, `*`) || strings.HasPrefix(s, `[]`) || strings.HasSuffix(s, `List`))
}

var standardHeaders []headerField

func init() {
	standardHeaders = []headerField{
		{
			name:     `keyUsage`,
			method:   `KeyUsage`,
			key:      `use`,
			typ:      `string`,
			comment:  `https://tools.ietf.org/html/rfc7517#section-4.2`,
			optional: true,
		},
		{
			name:      `keyops`,
			method:    `KeyOps`,
			typ:       `KeyOperationList`,
			key:       `key_ops`,
			comment:   `https://tools.ietf.org/html/rfc7517#section-4.3`,
			optional:  true,
			hasAccept: true,
		},
		{
			name:     `algorithm`,
			method:   `Algorithm`,
			typ:      `string`,
			key:      `alg`,
			optional: true,
			comment:  `https://tools.ietf.org/html/rfc7517#section-4.4`,
		},
		{
			name:     `keyID`,
			method:   `KeyID`,
			typ:      `string`,
			key:      `kid`,
			optional: true,
			comment:  `https://tools.ietf.org/html/rfc7515#section-4.1.4`,
		},
		{
			name:     `x509URL`,
			method:   `X509URL`,
			typ:      `string`,
			key:      `x5u`,
			optional: true,
			comment:  `https://tools.ietf.org/html/rfc7515#section-4.1.5`,
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
			optional:   true,
			returnType: `[]*x509.Certificate`,
		},
		{
			name:     `x509CertThumbprint`,
			method:   `X509CertThumbprint`,
			typ:      `string`,
			key:      `x5t`,
			optional: true,
			comment:  `https://tools.ietf.org/html/rfc7515#section-4.1.7`,
		},
		{
			name:     `x509CertThumbprintS256`,
			method:   `X509CertThumbprintS256`,
			typ:      `string`,
			key:      `x5t#S256`,
			optional: true,
			comment:  `https://tools.ietf.org/html/rfc7515#section-4.1.8`,
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
	keyType     string
}

type headerType struct {
	allHeaders []headerField
	headers    []headerField
	rawKeyType string
	name       string
	structName string
	ifName     string
}

var keyTypes = []keyType{
	{
		filename: `rsa_gen.go`,
		prefix:   `RSA`,
		keyType:  `jwa.RSA`,
		headerTypes: []headerType{
			{
				name:       `PublicKey`,
				rawKeyType: `*rsa.PublicKey`,
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
				name:       `PrivateKey`,
				rawKeyType: `*rsa.PrivateKey`,
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
		filename: `ecdsa_gen.go`,
		prefix:   `ECDSA`,
		keyType:  `jwa.EC`,
		headerTypes: []headerType{
			{
				name:       `PublicKey`,
				rawKeyType: `*ecdsa.PublicKey`,
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
				name:       `PrivateKey`,
				rawKeyType: `*ecdsa.PrivateKey`,
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
		filename: `symmetric_gen.go`,
		prefix:   `Symmetric`,
		keyType:  `jwa.OctetSeq`,
		headerTypes: []headerType{
			{
				name:       "SymmetricKey",
				structName: `symmetricKey`,
				ifName:     `SymmetricKey`,
				rawKeyType: `[]byte`,
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
	{
		filename: `okp_gen.go`,
		prefix:   `OKP`,
		keyType:  `jwa.OKP`,
		headerTypes: []headerType{
			{
				name:       "PublicKey",
				rawKeyType: `interface{}`,
				headers: []headerField{
					{
						name:   `x`,
						method: `X`,
						typ:    `[]byte`,
						key:    `x`,
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
				name:       "PrivateKey",
				rawKeyType: `interface{}`,
				headers: []headerField{
					{
						name:   `x`,
						method: `X`,
						typ:    `[]byte`,
						key:    `x`,
					},
					{
						name:   `d`,
						method: `D`,
						typ:    `[]byte`,
						key:    `d`,
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
}

func generateGenericHeaders() error {
	var buf bytes.Buffer

	fmt.Fprintf(&buf, "\n// This file is auto-generated. DO NOT EDIT")
	fmt.Fprintf(&buf, "\n\npackage jwk")

	fmt.Fprintf(&buf, "\n\nimport (")
	pkgs := []string{
		"crypto/x509",
		"fmt",
		"github.com/lestrrat-go/jwx/jwa",
		"github.com/pkg/errors",
	}
	for _, pkg := range pkgs {
		fmt.Fprintf(&buf, "\n%s", strconv.Quote(pkg))
	}
	fmt.Fprintf(&buf, "\n)")

	fmt.Fprintf(&buf, "\n\nconst (")
	fmt.Fprintf(&buf, "\nKeyTypeKey = \"kty\"")
	for _, f := range standardHeaders {
		fmt.Fprintf(&buf, "\n%sKey = %s", f.method, strconv.Quote(f.key))
	}
	fmt.Fprintf(&buf, "\n)") // end const

	fmt.Fprintf(&buf, "\n\n// Key defines the minimal interface for each of the")
	fmt.Fprintf(&buf, "\n// key types. Their use and implementation differ significantly")
	fmt.Fprintf(&buf, "\n// between each key types, so you should use type assertions")
	fmt.Fprintf(&buf, "\n// to perform more specific tasks with each key")
	fmt.Fprintf(&buf, "\ntype Key interface {")
	fmt.Fprintf(&buf, "\n// Get returns the value of a single field. The second boolean return value")
	fmt.Fprintf(&buf, "\n// will be false if the field is not stored in the source")
	fmt.Fprintf(&buf, "\n//\n// This method, which returns an `interface{}`, exists because")
	fmt.Fprintf(&buf, "\n// these objects can contain extra _arbitrary_ fields that users can")
	fmt.Fprintf(&buf, "\n// specify, and there is no way of knowing what type they could be")
	fmt.Fprintf(&buf, "\nGet(string) (interface{}, bool)")
	fmt.Fprintf(&buf, "\n\n// Set sets the value of a single field. Note that certain fields,")
	fmt.Fprintf(&buf, "\n// notably \"kty\", cannot be altered, but will not return an error")
	fmt.Fprintf(&buf, "\n//\n// This method, which takes an `interface{}`, exists because")
	fmt.Fprintf(&buf, "\n// these objects can contain extra _arbitrary_ fields that users can")
	fmt.Fprintf(&buf, "\n// specify, and there is no way of knowing what type they could be")
	fmt.Fprintf(&buf, "\nSet(string, interface{}) error")
	fmt.Fprintf(&buf, "\n\n// Remove removes the field associated with the specified key.")
	fmt.Fprintf(&buf, "\n// There is no way to remove the `kty` (key type). You will ALWAYS be left with one field in a jwk.Key.")
	fmt.Fprintf(&buf, "\nRemove(string) error")
	fmt.Fprintf(&buf, "\n\n// Raw creates the corresponding raw key. For example,")
	fmt.Fprintf(&buf, "\n// EC types would create *ecdsa.PublicKey or *ecdsa.PrivateKey,")
	fmt.Fprintf(&buf, "\n// and OctetSeq types create a []byte key.")
	fmt.Fprintf(&buf, "\n//\n// If you do not know the exact type of a jwk.Key before attempting")
	fmt.Fprintf(&buf, "\n// to obtain the raw key, you can simply pass a pointer to an")
	fmt.Fprintf(&buf, "\n// empty interface as the first argument.")
	fmt.Fprintf(&buf, "\n//\n// If you already know the exact type, it is recommended that you")
	fmt.Fprintf(&buf, "\n// pass a pointer to the zero value of the actual key type (e.g. &rsa.PrivateKey)")
	fmt.Fprintf(&buf, "\n// for efficiency.")
	fmt.Fprintf(&buf, "\nRaw(interface{}) error")
	fmt.Fprintf(&buf, "\n\n// Thumbprint returns the JWK thumbprint using the indicated")
	fmt.Fprintf(&buf, "\n// hashing algorithm, according to RFC 7638")
	fmt.Fprintf(&buf, "\nThumbprint(crypto.Hash) ([]byte, error)")
	fmt.Fprintf(&buf, "\n\n// Iterate returns an iterator that returns all keys and values.")
	fmt.Fprintf(&buf, "\n// See github.com/lestrrat-go/iter for a description of the iterator.")
	fmt.Fprintf(&buf, "\nIterate(ctx context.Context) HeaderIterator")
	fmt.Fprintf(&buf, "\n\n// Walk is a utility tool that allows a visitor to iterate all keys and values")
	fmt.Fprintf(&buf, "\nWalk(context.Context, HeaderVisitor) error")
	fmt.Fprintf(&buf, "\n\n// AsMap is a utility tool that returns a new map that contains the same fields as the source")
	fmt.Fprintf(&buf, "\nAsMap(context.Context) (map[string]interface{}, error)")
	fmt.Fprintf(&buf, "\n\n// PrivateParams returns the non-standard elements in the source structure")
	fmt.Fprintf(&buf, "\n// WARNING: DO NOT USE PrivateParams() IF YOU HAVE CONCURRENT CODE ACCESSING THEM.")
	fmt.Fprintf(&buf, "\n// Use `AsMap()` to get a copy of the entire header, or use `Iterate()` instead")
	fmt.Fprintf(&buf, "\nPrivateParams() map[string]interface{}")
	fmt.Fprintf(&buf, "\n\n// Clone creates a new instance of the same type")
	fmt.Fprintf(&buf, "\nClone() (Key, error)")
	fmt.Fprintf(&buf, "\n\nKeyType() jwa.KeyType")
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

	if err := codegen.WriteFile("interface_gen.go", &buf, codegen.WithFormatCode(true)); err != nil {
		if cfe, ok := err.(codegen.CodeFormatError); ok {
			fmt.Fprint(os.Stderr, cfe.Source())
		}
		return errors.Wrap(err, `failed to write to interface_gen.go`)
	}
	return nil
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
	pkgs := []string{
		"bytes",
		"context",
		"crypto/x509",
		"fmt",
		"sort",
		"strconv",

		"github.com/lestrrat-go/iter/mapiter",
		"github.com/lestrrat-go/jwx/internal/iter",
		"github.com/lestrrat-go/jwx/internal/base64",
		"github.com/lestrrat-go/jwx/internal/json",
		"github.com/lestrrat-go/jwx/internal/pool",
		"github.com/lestrrat-go/jwx/jwa",
		"github.com/pkg/errors",
	}
	for _, pkg := range pkgs {
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

	for i := 0; i < len(kt.headerTypes); i++ {
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
			structName = strings.ToLower(kt.prefix) + ht.name
		}
		ifName := ht.ifName
		if len(ifName) == 0 {
			ifName = kt.prefix + ht.name
		}

		fmt.Fprintf(&buf, "\n\ntype %s interface {", ifName)
		fmt.Fprintf(&buf, "\nKey")
		fmt.Fprintf(&buf, "\nFromRaw(%s) error", ht.rawKeyType)
		for _, header := range ht.headers {
			fmt.Fprintf(&buf, "\n%s() %s", header.method, header.typ)
		}
		fmt.Fprintf(&buf, "\n}")

		fmt.Fprintf(&buf, "\n\ntype %s struct {", structName)
		for _, header := range ht.allHeaders {
			fmt.Fprintf(&buf, "\n%s %s", header.name, fieldStorageType(header.typ))
			if len(header.comment) > 0 {
				fmt.Fprintf(&buf, " // %s", header.comment)
			}
		}
		fmt.Fprintf(&buf, "\nprivateParams map[string]interface{}")
		fmt.Fprintf(&buf, "\nmu *sync.RWMutex")
		fmt.Fprintf(&buf, "\n}")

		fmt.Fprintf(&buf, "\n\nfunc New%[1]s() %[1]s {", ifName)
		fmt.Fprintf(&buf, "\nreturn new%s()", ifName)
		fmt.Fprintf(&buf, "\n}")
		fmt.Fprintf(&buf, "\n\nfunc new%s() *%s {", ifName, structName)
		fmt.Fprintf(&buf, "\nreturn &%s{", structName)
		fmt.Fprintf(&buf, "\nmu: &sync.RWMutex{},")
		fmt.Fprintf(&buf, "\nprivateParams: make(map[string]interface{}),")
		fmt.Fprintf(&buf, "\n}")
		fmt.Fprintf(&buf, "\n}")

		fmt.Fprintf(&buf, "\n\nfunc (h %s) KeyType() jwa.KeyType {", structName)
		fmt.Fprintf(&buf, "\nreturn %s", kt.keyType)
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

		fmt.Fprintf(&buf, "\n\nfunc (h *%s) makePairs() []*HeaderPair {", structName)
		fmt.Fprintf(&buf, "\nh.mu.RLock()")
		fmt.Fprintf(&buf, "\ndefer h.mu.RUnlock()")

		// NOTE: building up an array is *slow*?
		fmt.Fprintf(&buf, "\n\nvar pairs []*HeaderPair")
		fmt.Fprintf(&buf, "\npairs = append(pairs, &HeaderPair{Key: \"kty\", Value: %s})", kt.keyType)
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
		fmt.Fprintf(&buf, "\nreturn pairs")
		fmt.Fprintf(&buf, "\n}") // end of (h *stdHeaders) iterate(...)

		fmt.Fprintf(&buf, "\n\nfunc (h *%s) PrivateParams() map[string]interface{} {", structName)
		fmt.Fprintf(&buf, "\nreturn h.privateParams")
		fmt.Fprintf(&buf, "\n}")

		fmt.Fprintf(&buf, "\n\nfunc (h *%s) Get(name string) (interface{}, bool) {", structName)
		fmt.Fprintf(&buf, "\nh.mu.RLock()")
		fmt.Fprintf(&buf, "\ndefer h.mu.RUnlock()")
		fmt.Fprintf(&buf, "\nswitch name {")
		fmt.Fprintf(&buf, "\ncase KeyTypeKey:")
		fmt.Fprintf(&buf, "\nreturn h.KeyType(), true")
		for _, f := range ht.allHeaders {
			if f.isStd {
				fmt.Fprintf(&buf, "\ncase %sKey:", f.method)
			} else {
				fmt.Fprintf(&buf, "\ncase %s%sKey:", kt.prefix, f.method)
			}

			fmt.Fprintf(&buf, "\nif h.%s == nil {", f.name)
			fmt.Fprintf(&buf, "\nreturn nil, false")
			fmt.Fprintf(&buf, "\n}")
			if f.hasGet {
				fmt.Fprintf(&buf, "\nreturn h.%s.Get(), true", f.name)
			} else if fieldStorageTypeIsIndirect(f.typ) {
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
		fmt.Fprintf(&buf, "\nh.mu.Lock()")
		fmt.Fprintf(&buf, "\ndefer h.mu.Unlock()")
		fmt.Fprintf(&buf, "\nreturn h.setNoLock(name, value)")
		fmt.Fprintf(&buf, "\n}")

		fmt.Fprintf(&buf, "\n\nfunc (h *%s) setNoLock(name string, value interface{}) error {", structName)
		fmt.Fprintf(&buf, "\nswitch name {")
		fmt.Fprintf(&buf, "\ncase \"kty\":")
		fmt.Fprintf(&buf, "\nreturn nil") // This is not great, but we just ignore it
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
			} else if f.name == `keyUsage` {
				fmt.Fprintf(&buf, "\nswitch v := value.(type) {")
				fmt.Fprintf(&buf, "\ncase KeyUsageType:")
				fmt.Fprintf(&buf, "\nswitch v {")
				fmt.Fprintf(&buf, "\ncase ForSignature, ForEncryption:")
				fmt.Fprintf(&buf, "\ntmp := v.String()")
				fmt.Fprintf(&buf, "\nh.keyUsage = &tmp")
				fmt.Fprintf(&buf, "\ndefault:")
				fmt.Fprintf(&buf, "\nreturn errors.Errorf(`invalid key usage type %%s`, v)")
				fmt.Fprintf(&buf, "\n}")
				fmt.Fprintf(&buf, "\ncase string:")
				fmt.Fprintf(&buf, "\nh.keyUsage = &v")
				fmt.Fprintf(&buf, "\ndefault:")
				fmt.Fprintf(&buf, "\nreturn errors.Errorf(`invalid key usage type %%s`, v)")
				fmt.Fprintf(&buf, "\n}")
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

		fmt.Fprintf(&buf, "\n\nfunc (k *%s) Remove(key string) error {", structName)
		fmt.Fprintf(&buf, "\nk.mu.Lock()")
		fmt.Fprintf(&buf, "\ndefer k.mu.Unlock()")
		fmt.Fprintf(&buf, "\nswitch key {")
		for _, f := range ht.allHeaders {
			var keyName string
			if f.isStd {
				keyName = f.method + "Key"
			} else {
				keyName = kt.prefix + f.method + "Key"
			}
			fmt.Fprintf(&buf, "\ncase %s:", keyName)
			fmt.Fprintf(&buf, "\nk.%s = nil", f.name)
		}
		fmt.Fprintf(&buf, "\ndefault:")
		fmt.Fprintf(&buf, "\ndelete(k.privateParams, key)")
		fmt.Fprintf(&buf, "\n}")
		fmt.Fprintf(&buf, "\nreturn nil") // currently unused, but who knows
		fmt.Fprintf(&buf, "\n}")

		fmt.Fprintf(&buf, "\n\nfunc (k *%s) Clone() (Key, error) {", structName)
		fmt.Fprintf(&buf, "\nreturn cloneKey(k)")
		fmt.Fprintf(&buf, "\n}")

		fmt.Fprintf(&buf, "\n\nfunc (h *%s) UnmarshalJSON(buf []byte) error {", structName)
		for _, f := range ht.allHeaders {
			fmt.Fprintf(&buf, "\nh.%s = nil", f.name)
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
		// kty is special. Hardcode it.
		fmt.Fprintf(&buf, "\ncase KeyTypeKey:")
		fmt.Fprintf(&buf, "\nval, err := json.ReadNextStringToken(dec)")
		fmt.Fprintf(&buf, "\nif err != nil {")
		fmt.Fprintf(&buf, "\nreturn errors.Wrap(err, `error reading token`)")
		fmt.Fprintf(&buf, "\n}")
		fmt.Fprintf(&buf, "\nif val != %s.String() {", kt.keyType)
		fmt.Fprintf(&buf, "\nreturn errors.Errorf(`invalid kty value for RSAPublicKey (%%s)`, val)")
		fmt.Fprintf(&buf, "\n}")

		for _, f := range ht.allHeaders {
			if f.typ == "string" {
				fmt.Fprintf(&buf, "\ncase %sKey:", f.method)
				fmt.Fprintf(&buf, "\nif err := json.AssignNextStringToken(&h.%s, dec); err != nil {", f.name)
				fmt.Fprintf(&buf, "\nreturn errors.Wrapf(err, `failed to decode value for key %%s`, %sKey)", f.method)
				fmt.Fprintf(&buf, "\n}")
			} else if f.typ == "[]byte" {
				name := f.method
				switch f.name {
				case "n", "e", "d", "p", "dp", "dq", "x", "y", "q", "qi", "octets":
					name = kt.prefix + f.method
				}
				fmt.Fprintf(&buf, "\ncase %sKey:", name)
				fmt.Fprintf(&buf, "\nif err := json.AssignNextBytesToken(&h.%s, dec); err != nil {", f.name)
				fmt.Fprintf(&buf, "\nreturn errors.Wrapf(err, `failed to decode value for key %%s`, %sKey)", name)
				fmt.Fprintf(&buf, "\n}")
			} else {
				name := f.method
				if f.name == "crv" {
					name = kt.prefix + f.method
				}
				fmt.Fprintf(&buf, "\ncase %sKey:", name)
				fmt.Fprintf(&buf, "\nvar decoded %s", f.typ)
				fmt.Fprintf(&buf, "\nif err := dec.Decode(&decoded); err != nil {")
				fmt.Fprintf(&buf, "\nreturn errors.Wrapf(err, `failed to decode value for key %%s`, %sKey)", name)
				fmt.Fprintf(&buf, "\n}")
				fmt.Fprintf(&buf, "\nh.%s = &decoded", f.name)
			}
		}
		fmt.Fprintf(&buf, "\ndefault:")
		fmt.Fprintf(&buf, "\ndecoded, err := registry.Decode(dec, tok)")
		fmt.Fprintf(&buf, "\nif err != nil {")
		fmt.Fprintf(&buf, "\nreturn err")
		fmt.Fprintf(&buf, "\n}")
		fmt.Fprintf(&buf, "\nh.setNoLock(tok, decoded)")
		fmt.Fprintf(&buf, "\n}")
		fmt.Fprintf(&buf, "\ndefault:")
		fmt.Fprintf(&buf, "\nreturn errors.Errorf(`invalid token %%T`, tok)")
		fmt.Fprintf(&buf, "\n}")
		fmt.Fprintf(&buf, "\n}")

		for _, f := range ht.allHeaders {
			if !f.optional {
				fmt.Fprintf(&buf, "\nif h.%s == nil {", f.name)
				fmt.Fprintf(&buf, "\nreturn errors.Errorf(`required field %s is missing`)", f.key)
				fmt.Fprintf(&buf, "\n}")
			}
		}

		fmt.Fprintf(&buf, "\nreturn nil")
		fmt.Fprintf(&buf, "\n}")

		fmt.Fprintf(&buf, "\n\nfunc (h %s) MarshalJSON() ([]byte, error) {", structName)
		fmt.Fprintf(&buf, "\nctx, cancel := context.WithCancel(context.Background())")
		fmt.Fprintf(&buf, "\ndefer cancel()")
		fmt.Fprintf(&buf, "\ndata := make(map[string]interface{})")
		fmt.Fprintf(&buf, "\nfields := make([]string, 0, %d)", len(ht.allHeaders))
		fmt.Fprintf(&buf, "\nfor iter := h.Iterate(ctx); iter.Next(ctx); {")
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
		fmt.Fprintf(&buf, "\nbuf.WriteRune(',')")
		fmt.Fprintf(&buf, "\n}")
		fmt.Fprintf(&buf, "\nbuf.WriteRune('\"')")
		fmt.Fprintf(&buf, "\nbuf.WriteString(f)")
		fmt.Fprintf(&buf, "\nbuf.WriteString(`\":`)")
		fmt.Fprintf(&buf, "\nv := data[f]")
		fmt.Fprintf(&buf, "\nswitch v := v.(type) {")
		fmt.Fprintf(&buf, "\ncase []byte:")
		fmt.Fprintf(&buf, "\nbuf.WriteRune('\"')")
		fmt.Fprintf(&buf, "\nbuf.WriteString(base64.EncodeToString(v))")
		fmt.Fprintf(&buf, "\nbuf.WriteRune('\"')")
		fmt.Fprintf(&buf, "\ndefault:")
		fmt.Fprintf(&buf, "\nif err := enc.Encode(v); err != nil {")
		fmt.Fprintf(&buf, "\nreturn nil, errors.Wrapf(err, `failed to encode value for field %%s`, f)")
		fmt.Fprintf(&buf, "\n}")
		fmt.Fprintf(&buf, "\nbuf.Truncate(buf.Len()-1)")
		fmt.Fprintf(&buf, "\n}")
		fmt.Fprintf(&buf, "\n}")
		fmt.Fprintf(&buf, "\nbuf.WriteByte('}')")
		fmt.Fprintf(&buf, "\nret := make([]byte, buf.Len())")
		fmt.Fprintf(&buf, "\ncopy(ret, buf.Bytes())")
		fmt.Fprintf(&buf, "\nreturn ret, nil")
		fmt.Fprintf(&buf, "\n}")

		fmt.Fprintf(&buf, "\n\nfunc (h *%s) Iterate(ctx context.Context) HeaderIterator {", structName)
		fmt.Fprintf(&buf, "\npairs := h.makePairs()")
		fmt.Fprintf(&buf, "\nch := make(chan *HeaderPair, len(pairs))")
		fmt.Fprintf(&buf, "\ngo func(ctx context.Context, ch chan *HeaderPair, pairs []*HeaderPair) {")
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

		fmt.Fprintf(&buf, "\n\nfunc (h *%s) Walk(ctx context.Context, visitor HeaderVisitor) error {", structName)
		fmt.Fprintf(&buf, "\nreturn iter.WalkMap(ctx, h, visitor)")
		fmt.Fprintf(&buf, "\n}")

		fmt.Fprintf(&buf, "\n\nfunc (h *%s) AsMap(ctx context.Context) (map[string]interface{}, error) {", structName)
		fmt.Fprintf(&buf, "\nreturn iter.AsMap(ctx, h)")
		fmt.Fprintf(&buf, "\n}")
	}

	if err := codegen.WriteFile(kt.filename, &buf, codegen.WithFormatCode(true)); err != nil {
		if cfe, ok := err.(codegen.CodeFormatError); ok {
			fmt.Fprint(os.Stderr, cfe.Source())
		}
		return errors.Wrapf(err, `failed to write to %s`, kt.filename)
	}
	return nil
}
