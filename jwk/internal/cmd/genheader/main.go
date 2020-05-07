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
	return s == "KeyOperationList" || !(strings.HasPrefix(s, `*`) || strings.HasPrefix(s, `[]`) || strings.HasSuffix(s, `List`))
}

var standardHeaders []headerField

func init() {
	standardHeaders = []headerField{
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
	keyType     string
}

type headerType struct {
	allHeaders []headerField
	headers    []headerField
	ifMethods  []string
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
				ifMethods: []string{
					`PublicKey() (RSAPublicKey, error)`,
				},
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
				ifMethods: []string{
					`PublicKey() (ECDSAPublicKey, error)`,
				},
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
	fmt.Fprintf(&buf, "\n// notably \"kty\" cannot be altered, but will not return an error")
	fmt.Fprintf(&buf, "\n//\n// This method, which takes an `interface{}`, exists because")
	fmt.Fprintf(&buf, "\n// these objects can contain extra _arbitrary_ fields that users can")
	fmt.Fprintf(&buf, "\n// specify, and there is no way of knowing what type they could be")
	fmt.Fprintf(&buf, "\nSet(string, interface{}) error")
	fmt.Fprintf(&buf, "\n\n// Raw creates the corresponding raw key. For example,")
	fmt.Fprintf(&buf, "\n// EC types would create *ecdsa.PublicKey or *ecdsa.PrivateKey,")
	fmt.Fprintf(&buf, "\n// and OctetSeq types create a []byte key.")
	fmt.Fprintf(&buf, "\n//\n// If you do not know the exact type of a jwk.Key before attempting")
	fmt.Fprintf(&buf, "\n// to obtain the raw key, you can simply pass a pointer to an")
	fmt.Fprintf(&buf, "\n// empty interface as the first argument.")
	fmt.Fprintf(&buf, "\n//\n// If you already know the exact type, it is recommended that you")
	fmt.Fprintf(&buf, "\n// pass a pointer to the actual key type (e.g. *rsa.PrivateKey, *ecdsa.PublicKey")
	fmt.Fprintf(&buf, "\n// for efficiency")
	fmt.Fprintf(&buf, "\nRaw(interface{}) error")
	fmt.Fprintf(&buf, "\n\n// Thumbprint returns the JWK thumbprint using the indicated")
	fmt.Fprintf(&buf, "\n// hashing algorithm, according to RFC 7638")
	fmt.Fprintf(&buf, "\nThumbprint(crypto.Hash) ([]byte, error)")
	fmt.Fprintf(&buf, "\n\n// Iterate returns an iterator that returns all keys and values")
	fmt.Fprintf(&buf, "\nIterate(ctx context.Context) HeaderIterator")
	fmt.Fprintf(&buf, "\n\n// Walk is a utility tool that allows a visitor to iterate all keys and values")
	fmt.Fprintf(&buf, "\nWalk(context.Context, HeaderVisitor) error")
	fmt.Fprintf(&buf, "\n\n// AsMap is a utility tool returns a map that contains the same fields as the source")
	fmt.Fprintf(&buf, "\nAsMap(context.Context) (map[string]interface{}, error)")
	fmt.Fprintf(&buf, "\n\n// PrivateParams returns the non-standard elements in the source structure")
	fmt.Fprintf(&buf, "\nPrivateParams() map[string]interface{}")
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

	return codegen.WriteFormattedCodeToFile("interface_gen.go", &buf)
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
		"crypto/x509",
		"fmt",
		"github.com/lestrrat-go/jwx/internal/base64",
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
		for _, method := range ht.ifMethods {
			fmt.Fprintf(&buf, "\n%s", method)
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
		fmt.Fprintf(&buf, "\n}")

		// Proxy is used when unmarshaling headers
		fmt.Fprintf(&buf, "\n\ntype %s%sMarshalProxy struct {", strings.ToLower(kt.prefix), ht.name)
		fmt.Fprintf(&buf, "\nXkeyType jwa.KeyType `json:\"kty\"`")
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

		// Generate a function that iterates through all of the keys
		// in this header.
		fmt.Fprintf(&buf, "\n\nfunc (h *%s) iterate(ctx context.Context, ch chan *HeaderPair) {", structName)
		fmt.Fprintf(&buf, "\ndefer close(ch)")

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
		fmt.Fprintf(&buf, "\nvar proxy %s%sMarshalProxy", strings.ToLower(kt.prefix), ht.name)
		fmt.Fprintf(&buf, "\nif err := json.Unmarshal(buf, &proxy); err != nil {")
		fmt.Fprintf(&buf, "\nreturn errors.Wrap(err, `failed to unmarshal %s`)", structName)
		fmt.Fprintf(&buf, "\n}")

		fmt.Fprintf(&buf, "\nif proxy.XkeyType != %s {", kt.keyType)
		fmt.Fprintf(&buf, "\nreturn errors.Errorf(`invalid kty value for %s (%%s)`, proxy.XkeyType)", ifName)
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
		fmt.Fprintf(&buf, "\ndelete(m, `kty`)")
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
		fmt.Fprintf(&buf, "\nvar proxy %s%sMarshalProxy", strings.ToLower(kt.prefix), ht.name)
		fmt.Fprintf(&buf, "\nproxy.XkeyType = %s", kt.keyType)
		for _, f := range ht.allHeaders {
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
				if f.key == "kty" {
					fmt.Fprintf(&buf, "\nif proxy.X%s == nil {", f.name)
					fmt.Fprintf(&buf, "\nv := %s", kt.keyType)
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

	return codegen.WriteFormattedCodeToFile(kt.filename, &buf)
}
