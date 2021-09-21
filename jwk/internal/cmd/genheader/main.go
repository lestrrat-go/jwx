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

	o := codegen.NewOutput(&buf)
	o.L("// This file is auto-generated. DO NOT EDIT")
	o.LL("package jwk")

	o.LL("import (")
	pkgs := []string{
		"crypto/x509",
		"fmt",
		"github.com/lestrrat-go/jwx/jwa",
		"github.com/pkg/errors",
	}
	for _, pkg := range pkgs {
		o.L("%s", strconv.Quote(pkg))
	}
	o.L(")")

	o.LL("const (")
	o.L("KeyTypeKey = \"kty\"")
	for _, f := range standardHeaders {
		o.L("%sKey = %s", f.method, strconv.Quote(f.key))
	}

	o.L(")") // end const

	o.LL("// Key defines the minimal interface for each of the")
	o.L("// key types. Their use and implementation differ significantly")
	o.L("// between each key types, so you should use type assertions")
	o.L("// to perform more specific tasks with each key")
	o.L("type Key interface {")
	o.L("// Get returns the value of a single field. The second boolean return value")
	o.L("// will be false if the field is not stored in the source")
	o.L("//\n// This method, which returns an `interface{}`, exists because")
	o.L("// these objects can contain extra _arbitrary_ fields that users can")
	o.L("// specify, and there is no way of knowing what type they could be")
	o.L("Get(string) (interface{}, bool)")
	o.LL("// Set sets the value of a single field. Note that certain fields,")
	o.L("// notably \"kty\", cannot be altered, but will not return an error")
	o.L("//\n// This method, which takes an `interface{}`, exists because")
	o.L("// these objects can contain extra _arbitrary_ fields that users can")
	o.L("// specify, and there is no way of knowing what type they could be")
	o.L("Set(string, interface{}) error")
	o.LL("// Remove removes the field associated with the specified key.")
	o.L("// There is no way to remove the `kty` (key type). You will ALWAYS be left with one field in a jwk.Key.")
	o.L("Remove(string) error")
	o.LL("// Raw creates the corresponding raw key. For example,")
	o.L("// EC types would create *ecdsa.PublicKey or *ecdsa.PrivateKey,")
	o.L("// and OctetSeq types create a []byte key.")
	o.L("//\n// If you do not know the exact type of a jwk.Key before attempting")
	o.L("// to obtain the raw key, you can simply pass a pointer to an")
	o.L("// empty interface as the first argument.")
	o.L("//\n// If you already know the exact type, it is recommended that you")
	o.L("// pass a pointer to the zero value of the actual key type (e.g. &rsa.PrivateKey)")
	o.L("// for efficiency.")
	o.L("Raw(interface{}) error")
	o.LL("// Thumbprint returns the JWK thumbprint using the indicated")
	o.L("// hashing algorithm, according to RFC 7638")
	o.L("Thumbprint(crypto.Hash) ([]byte, error)")
	o.LL("// Iterate returns an iterator that returns all keys and values.")
	o.L("// See github.com/lestrrat-go/iter for a description of the iterator.")
	o.L("Iterate(ctx context.Context) HeaderIterator")
	o.LL("// Walk is a utility tool that allows a visitor to iterate all keys and values")
	o.L("Walk(context.Context, HeaderVisitor) error")
	o.LL("// AsMap is a utility tool that returns a new map that contains the same fields as the source")
	o.L("AsMap(context.Context) (map[string]interface{}, error)")
	o.LL("// PrivateParams returns the non-standard elements in the source structure")
	o.L("// WARNING: DO NOT USE PrivateParams() IF YOU HAVE CONCURRENT CODE ACCESSING THEM.")
	o.L("// Use `AsMap()` to get a copy of the entire header, or use `Iterate()` instead")
	o.L("PrivateParams() map[string]interface{}")
	o.LL("// Clone creates a new instance of the same type")
	o.L("Clone() (Key, error)")
	o.LL("KeyType() jwa.KeyType")
	o.LL("// PublicKey creates the corresponding PublicKey type for this object.")
	o.L("// All fields are copied onto the new public key, except for those that are not allowed.")
	o.L("//\n// If the key is already a public key, it returns a new copy minus the disallowed fields as above.")
	o.L("PublicKey() (Key, error)")
	for _, f := range standardHeaders {
		o.L("%s() ", f.method)
		if f.returnType != "" {
			o.R("%s", f.returnType)
		} else if f.IsPointer() && f.noDeref {
			o.R("%s", f.typ)
		} else {
			o.R("%s", f.PointerElem())
		}
	}
	o.LL("makePairs() []*HeaderPair")
	o.L("}")

	if err := o.WriteFile("interface_gen.go", codegen.WithFormatCode(true)); err != nil {
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

	o := codegen.NewOutput(&buf)
	o.L("// This file is auto-generated. DO NOT EDIT")
	o.LL("package jwk")

	o.LL("import (")
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
		o.L("%s", strconv.Quote(pkg))
	}
	o.L(")")

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

	o.LL("const (")
	for _, f := range constants {
		o.L("%s%sKey = %s", kt.prefix, f.method, strconv.Quote(f.key))
	}
	o.L(")") // end const

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

		o.LL("type %s interface {", ifName)
		o.L("Key")
		o.L("FromRaw(%s) error", ht.rawKeyType)
		for _, header := range ht.headers {
			o.L("%s() %s", header.method, header.typ)
		}
		o.L("}")

		o.LL("type %s struct {", structName)
		for _, header := range ht.allHeaders {
			o.L("%s %s", header.name, fieldStorageType(header.typ))
			if len(header.comment) > 0 {
				o.R(" // %s", header.comment)
			}
		}
		o.L("privateParams map[string]interface{}")
		o.L("mu *sync.RWMutex")
		o.L("dc DecodeCtx")
		o.L("}")

		o.LL("func New%[1]s() %[1]s {", ifName)
		o.L("return new%s()", ifName)
		o.L("}")
		o.LL("func new%s() *%s {", ifName, structName)
		o.L("return &%s{", structName)
		o.L("mu: &sync.RWMutex{},")
		o.L("privateParams: make(map[string]interface{}),")
		o.L("}")
		o.L("}")

		o.LL("func (h %s) KeyType() jwa.KeyType {", structName)
		o.L("return %s", kt.keyType)
		o.L("}")

		for _, f := range ht.allHeaders {
			o.LL("func (h *%s) %s() ", structName, f.method)
			if f.returnType != "" {
				o.R("%s", f.returnType)
			} else if f.IsPointer() && f.noDeref {
				o.R("%s", f.typ)
			} else {
				o.R("%s", f.PointerElem())
			}
			o.R(" {")

			if f.hasGet {
				o.L("if h.%s != nil {", f.name)
				o.L("return h.%s.Get()", f.name)
				o.L("}")
				o.L("return %s", zeroval(f.PointerElem()))
			} else if !f.IsPointer() {
				if fieldStorageTypeIsIndirect(f.typ) {
					o.L("if h.%s != nil {", f.name)
					o.L("return *(h.%s)", f.name)
					o.L("}")
					o.L("return %s", zeroval(f.PointerElem()))
				} else {
					o.L("return h.%s", f.name)
				}
			}
			o.L("}") // func (h *stdHeaders) %s() %s
		}

		o.LL("func (h *%s) makePairs() []*HeaderPair {", structName)
		o.L("h.mu.RLock()")
		o.L("defer h.mu.RUnlock()")

		// NOTE: building up an array is *slow*?
		o.LL("var pairs []*HeaderPair")
		o.L("pairs = append(pairs, &HeaderPair{Key: \"kty\", Value: %s})", kt.keyType)
		for _, f := range ht.allHeaders {
			var keyName string
			if f.isStd {
				keyName = f.method + "Key"
			} else {
				keyName = kt.prefix + f.method + "Key"
			}
			o.L("if h.%s != nil {", f.name)
			if fieldStorageTypeIsIndirect(f.typ) {
				o.L("pairs = append(pairs, &HeaderPair{Key: %s, Value: *(h.%s)})", keyName, f.name)
			} else {
				o.L("pairs = append(pairs, &HeaderPair{Key: %s, Value: h.%s})", keyName, f.name)
			}
			o.L("}")
		}
		o.L("for k, v := range h.privateParams {")
		o.L("pairs = append(pairs, &HeaderPair{Key: k, Value: v})")
		o.L("}")
		o.L("return pairs")
		o.L("}") // end of (h *stdHeaders) iterate(...)

		o.LL("func (h *%s) PrivateParams() map[string]interface{} {", structName)
		o.L("return h.privateParams")
		o.L("}")

		o.LL("func (h *%s) Get(name string) (interface{}, bool) {", structName)
		o.L("h.mu.RLock()")
		o.L("defer h.mu.RUnlock()")
		o.L("switch name {")
		o.L("case KeyTypeKey:")
		o.L("return h.KeyType(), true")
		for _, f := range ht.allHeaders {
			if f.isStd {
				o.L("case %sKey:", f.method)
			} else {
				o.L("case %s%sKey:", kt.prefix, f.method)
			}

			o.L("if h.%s == nil {", f.name)
			o.L("return nil, false")
			o.L("}")
			if f.hasGet {
				o.L("return h.%s.Get(), true", f.name)
			} else if fieldStorageTypeIsIndirect(f.typ) {
				o.L("return *(h.%s), true", f.name)
			} else {
				o.L("return h.%s, true", f.name)
			}
		}
		o.L("default:")
		o.L("v, ok := h.privateParams[name]")
		o.L("return v, ok")
		o.L("}") // end switch name
		o.L("}") // func (h *%s) Get(name string) (interface{}, bool)

		o.LL("func (h *%s) Set(name string, value interface{}) error {", structName)
		o.L("h.mu.Lock()")
		o.L("defer h.mu.Unlock()")
		o.L("return h.setNoLock(name, value)")
		o.L("}")

		o.LL("func (h *%s) setNoLock(name string, value interface{}) error {", structName)
		o.L("switch name {")
		o.L("case \"kty\":")
		o.L("return nil") // This is not great, but we just ignore it
		for _, f := range ht.allHeaders {
			var keyName string
			if f.isStd {
				keyName = f.method + "Key"
			} else {
				keyName = kt.prefix + f.method + "Key"
			}
			o.L("case %s:", keyName)
			if f.name == `algorithm` {
				o.L("switch v := value.(type) {")
				o.L("case string:")
				o.L("h.algorithm = &v")
				o.L("case fmt.Stringer:")
				o.L("tmp := v.String()")
				o.L("h.algorithm = &tmp")
				o.L("default:")
				o.L("return errors.Errorf(`invalid type for %%s key: %%T`, %s, value)", keyName)
				o.L("}")
				o.L("return nil")
			} else if f.name == `keyUsage` {
				o.L("switch v := value.(type) {")
				o.L("case KeyUsageType:")
				o.L("switch v {")
				o.L("case ForSignature, ForEncryption:")
				o.L("tmp := v.String()")
				o.L("h.keyUsage = &tmp")
				o.L("default:")
				o.L("return errors.Errorf(`invalid key usage type %%s`, v)")
				o.L("}")
				o.L("case string:")
				o.L("h.keyUsage = &v")
				o.L("default:")
				o.L("return errors.Errorf(`invalid key usage type %%s`, v)")
				o.L("}")
			} else if f.hasAccept {
				o.L("var acceptor %s", f.typ)
				o.L("if err := acceptor.Accept(value); err != nil {")
				o.L("return errors.Wrapf(err, `invalid value for %%s key`, %s)", keyName)
				o.L("}") // end if err := h.%s.Accept(value)
				if fieldStorageTypeIsIndirect(f.typ) {
					o.L("h.%s = &acceptor", f.name)
				} else {
					o.L("h.%s = acceptor", f.name)
				}
				o.L("return nil")
			} else {
				o.L("if v, ok := value.(%s); ok {", f.typ)
				if fieldStorageTypeIsIndirect(f.typ) {
					o.L("h.%s = &v", f.name)
				} else {
					o.L("h.%s = v", f.name)
				}
				o.L("return nil")
				o.L("}") // end if v, ok := value.(%s)
				o.L("return errors.Errorf(`invalid value for %%s key: %%T`, %s, value)", keyName)
			}
		}
		o.L("default:")
		o.L("if h.privateParams == nil {")
		o.L("h.privateParams = map[string]interface{}{}")
		o.L("}") // end if h.privateParams == nil
		o.L("h.privateParams[name] = value")
		o.L("}") // end switch name
		o.L("return nil")
		o.L("}") // end func (h *%s) Set(name string, value interface{})

		o.LL("func (k *%s) Remove(key string) error {", structName)
		o.L("k.mu.Lock()")
		o.L("defer k.mu.Unlock()")
		o.L("switch key {")
		for _, f := range ht.allHeaders {
			var keyName string
			if f.isStd {
				keyName = f.method + "Key"
			} else {
				keyName = kt.prefix + f.method + "Key"
			}
			o.L("case %s:", keyName)
			o.L("k.%s = nil", f.name)
		}
		o.L("default:")
		o.L("delete(k.privateParams, key)")
		o.L("}")
		o.L("return nil") // currently unused, but who knows
		o.L("}")

		o.LL("func (k *%s) Clone() (Key, error) {", structName)
		o.L("return cloneKey(k)")
		o.L("}")

		o.LL("func (k *%s) DecodeCtx() DecodeCtx {", structName)
		o.L("k.mu.RLock()")
		o.L("defer k.mu.RUnlock()")
		o.L("return k.dc")
		o.L("}")

		o.LL("func (k *%s) SetDecodeCtx(dc DecodeCtx) {", structName)
		o.L("k.mu.Lock()")
		o.L("defer k.mu.Unlock()")
		o.L("k.dc = dc")
		o.L("}")

		o.LL("func (h *%s) UnmarshalJSON(buf []byte) error {", structName)
		for _, f := range ht.allHeaders {
			o.L("h.%s = nil", f.name)
		}

		o.L("dec := json.NewDecoder(bytes.NewReader(buf))")
		o.L("LOOP:")
		o.L("for {")
		o.L("tok, err := dec.Token()")
		o.L("if err != nil {")
		o.L("return errors.Wrap(err, `error reading token`)")
		o.L("}")
		o.L("switch tok := tok.(type) {")
		o.L("case json.Delim:")
		o.L("// Assuming we're doing everything correctly, we should ONLY")
		o.L("// get either '{' or '}' here.")
		o.L("if tok == '}' { // End of object")
		o.L("break LOOP")
		o.L("} else if tok != '{' {")
		o.L("return errors.Errorf(`expected '{', but got '%%c'`, tok)")
		o.L("}")
		o.L("case string: // Objects can only have string keys")
		o.L("switch tok {")
		// kty is special. Hardcode it.
		o.L("case KeyTypeKey:")
		o.L("val, err := json.ReadNextStringToken(dec)")
		o.L("if err != nil {")
		o.L("return errors.Wrap(err, `error reading token`)")
		o.L("}")
		o.L("if val != %s.String() {", kt.keyType)
		o.L("return errors.Errorf(`invalid kty value for RSAPublicKey (%%s)`, val)")
		o.L("}")

		for _, f := range ht.allHeaders {
			if f.typ == "string" {
				o.L("case %sKey:", f.method)
				o.L("if err := json.AssignNextStringToken(&h.%s, dec); err != nil {", f.name)
				o.L("return errors.Wrapf(err, `failed to decode value for key %%s`, %sKey)", f.method)
				o.L("}")
			} else if f.typ == "[]byte" {
				name := f.method
				switch f.name {
				case "n", "e", "d", "p", "dp", "dq", "x", "y", "q", "qi", "octets":
					name = kt.prefix + f.method
				}
				o.L("case %sKey:", name)
				o.L("if err := json.AssignNextBytesToken(&h.%s, dec); err != nil {", f.name)
				o.L("return errors.Wrapf(err, `failed to decode value for key %%s`, %sKey)", name)
				o.L("}")
			} else {
				name := f.method
				if f.name == "crv" {
					name = kt.prefix + f.method
				}
				o.L("case %sKey:", name)
				o.L("var decoded %s", f.typ)
				o.L("if err := dec.Decode(&decoded); err != nil {")
				o.L("return errors.Wrapf(err, `failed to decode value for key %%s`, %sKey)", name)
				o.L("}")
				o.L("h.%s = &decoded", f.name)
			}
		}
		o.L("default:")
		// This looks like bad code, but we're unrolling things for maximum
		// runtime efficiency
		o.L("if dc := h.dc; dc != nil {")
		o.L("if localReg := dc.Registry(); localReg != nil {")
		o.L("decoded, err := localReg.Decode(dec, tok)")
		o.L("if err == nil {")
		o.L("h.setNoLock(tok, decoded)")
		o.L("continue")
		o.L("}")
		o.L("}")
		o.L("}")

		o.L("decoded, err := registry.Decode(dec, tok)")
		o.L("if err == nil {")
		o.L("h.setNoLock(tok, decoded)")
		o.L("continue")
		o.L("}")
		o.L("return errors.Wrapf(err, `could not decode field %%s`, tok)")
		o.L("}")
		o.L("default:")
		o.L("return errors.Errorf(`invalid token %%T`, tok)")
		o.L("}")
		o.L("}")

		for _, f := range ht.allHeaders {
			if !f.optional {
				o.L("if h.%s == nil {", f.name)
				o.L("return errors.Errorf(`required field %s is missing`)", f.key)
				o.L("}")
			}
		}

		o.L("return nil")
		o.L("}")

		o.LL("func (h %s) MarshalJSON() ([]byte, error) {", structName)
		o.L("data := make(map[string]interface{})")
		o.L("fields := make([]string, 0, %d)", len(ht.allHeaders))
		o.L("for _, pair := range h.makePairs() {")
		o.L("fields = append(fields, pair.Key.(string))")
		o.L("data[pair.Key.(string)] = pair.Value")
		o.L("}")
		o.LL("sort.Strings(fields)")
		o.L("buf := pool.GetBytesBuffer()")
		o.L("defer pool.ReleaseBytesBuffer(buf)")
		o.L("buf.WriteByte('{')")
		o.L("enc := json.NewEncoder(buf)")
		o.L("for i, f := range fields {")
		o.L("if i > 0 {")
		o.L("buf.WriteRune(',')")
		o.L("}")
		o.L("buf.WriteRune('\"')")
		o.L("buf.WriteString(f)")
		o.L("buf.WriteString(`\":`)")
		o.L("v := data[f]")
		o.L("switch v := v.(type) {")
		o.L("case []byte:")
		o.L("buf.WriteRune('\"')")
		o.L("buf.WriteString(base64.EncodeToString(v))")
		o.L("buf.WriteRune('\"')")
		o.L("default:")
		o.L("if err := enc.Encode(v); err != nil {")
		o.L("return nil, errors.Wrapf(err, `failed to encode value for field %%s`, f)")
		o.L("}")
		o.L("buf.Truncate(buf.Len()-1)")
		o.L("}")
		o.L("}")
		o.L("buf.WriteByte('}')")
		o.L("ret := make([]byte, buf.Len())")
		o.L("copy(ret, buf.Bytes())")
		o.L("return ret, nil")
		o.L("}")

		o.LL("func (h *%s) Iterate(ctx context.Context) HeaderIterator {", structName)
		o.L("pairs := h.makePairs()")
		o.L("ch := make(chan *HeaderPair, len(pairs))")
		o.L("go func(ctx context.Context, ch chan *HeaderPair, pairs []*HeaderPair) {")
		o.L("defer close(ch)")
		o.L("for _, pair := range pairs {")
		o.L("select {")
		o.L("case <-ctx.Done():")
		o.L("return")
		o.L("case ch<-pair:")
		o.L("}")
		o.L("}")
		o.L("}(ctx, ch, pairs)")
		o.L("return mapiter.New(ch)")
		o.L("}")

		o.LL("func (h *%s) Walk(ctx context.Context, visitor HeaderVisitor) error {", structName)
		o.L("return iter.WalkMap(ctx, h, visitor)")
		o.L("}")

		o.LL("func (h *%s) AsMap(ctx context.Context) (map[string]interface{}, error) {", structName)
		o.L("return iter.AsMap(ctx, h)")
		o.L("}")
	}

	if err := o.WriteFile(kt.filename, codegen.WithFormatCode(true)); err != nil {
		if cfe, ok := err.(codegen.CodeFormatError); ok {
			fmt.Fprint(os.Stderr, cfe.Source())
		}
		return errors.Wrapf(err, `failed to write to %s`, kt.filename)
	}
	return nil
}
