package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/lestrrat-go/codegen"
)

func main() {
	if err := _main(); err != nil {
		log.Printf("%s", err)
		os.Exit(1)
	}
}

func _main() error {
	typs := []typ{
		{
			name:     `CompressionAlgorithm`,
			comment:  `CompressionAlgorithm represents the compression algorithms as described in https://tools.ietf.org/html/rfc7518#section-7.3`,
			filename: `compression_gen.go`,
			elements: []element{
				{
					name:    `NoCompress`,
					value:   ``,
					comment: `No compression`,
				},
				{
					name:    `Deflate`,
					value:   `DEF`,
					comment: `DEFLATE (RFC 1951)`,
				},
			},
		},
		{
			name:     `ContentEncryptionAlgorithm`,
			comment:  `ContentEncryptionAlgorithm represents the various encryption algorithms as described in https://tools.ietf.org/html/rfc7518#section-5`,
			filename: `content_encryption_gen.go`,
			elements: []element{
				{
					name:    `A128CBC_HS256`,
					value:   `A128CBC-HS256`,
					comment: `AES-CBC + HMAC-SHA256 (128)`,
				},
				{
					name:    `A192CBC_HS384`,
					value:   `A192CBC-HS384`,
					comment: `AES-CBC + HMAC-SHA384 (192)`,
				},
				{
					name:    `A256CBC_HS512`,
					value:   `A256CBC-HS512`,
					comment: `AES-CBC + HMAC-SHA512 (256)`,
				},
				{
					name:    `A128GCM`,
					value:   `A128GCM`,
					comment: `AES-GCM (128)`,
				},
				{
					name:    `A192GCM`,
					value:   `A192GCM`,
					comment: `AES-GCM (192)`,
				},
				{
					name:    `A256GCM`,
					value:   `A256GCM`,
					comment: `AES-GCM (256)`,
				},
			},
		},
		{
			name:     `KeyType`,
			comment:  `KeyType represents the key type ("kty") that are supported`,
			filename: "key_type_gen.go",
			elements: []element{
				{
					name:    `InvalidKeyType`,
					value:   ``,
					comment: `Invalid KeyType`,
					invalid: true,
				},
				{
					name:    `EC`,
					value:   `EC`,
					comment: `Elliptic Curve`,
				},
				{
					name:    `RSA`,
					value:   `RSA`,
					comment: `RSA`,
				},
				{
					name:    `OctetSeq`,
					value:   `oct`,
					comment: `Octet sequence (used to represent symmetric keys)`,
				},
				{
					name:    `OKP`,
					value:   `OKP`,
					comment: `Octet string key pairs`,
				},
			},
		},
		{
			name:     `EllipticCurveAlgorithm`,
			comment:  `EllipticCurveAlgorithm represents the algorithms used for EC keys`,
			filename: `elliptic_gen.go`,
			elements: []element{
				{
					name:    `InvalidEllipticCurve`,
					value:   `P-invalid`,
					invalid: true,
				},
				{
					name:  `P256`,
					value: `P-256`,
				},
				{
					name:  `P384`,
					value: `P-384`,
				},
				{
					name:  `P521`,
					value: `P-521`,
				},
				{
					name:  `Ed25519`,
					value: `Ed25519`,
				},
				{
					name:  `Ed448`,
					value: `Ed448`,
				},
				{
					name:  `X25519`,
					value: `X25519`,
				},
				{
					name:  `X448`,
					value: `X448`,
				},
			},
		},
		{
			name:     `SignatureAlgorithm`,
			comment:  `SignatureAlgorithm represents the various signature algorithms as described in https://tools.ietf.org/html/rfc7518#section-3.1`,
			filename: `signature_gen.go`,
			elements: []element{
				{
					name:  `NoSignature`,
					value: "none",
				},
				{
					name:    `HS256`,
					value:   "HS256",
					comment: `HMAC using SHA-256`,
				},
				{
					name:    `HS384`,
					value:   `HS384`,
					comment: `HMAC using SHA-384`,
				},
				{
					name:    `HS512`,
					value:   "HS512",
					comment: `HMAC using SHA-512`,
				},
				{
					name:    `RS256`,
					value:   `RS256`,
					comment: `RSASSA-PKCS-v1.5 using SHA-256`,
				},
				{
					name:    `RS384`,
					value:   `RS384`,
					comment: `RSASSA-PKCS-v1.5 using SHA-384`,
				},
				{
					name:    `RS512`,
					value:   `RS512`,
					comment: `RSASSA-PKCS-v1.5 using SHA-512`,
				},
				{
					name:    `ES256`,
					value:   `ES256`,
					comment: `ECDSA using P-256 and SHA-256`,
				},
				{
					name:    `ES384`,
					value:   `ES384`,
					comment: `ECDSA using P-384 and SHA-384`,
				},
				{
					name:    `ES512`,
					value:   "ES512",
					comment: `ECDSA using P-521 and SHA-512`,
				},
				{
					name:    `ES256K`,
					value:   "ES256K",
					comment: `ECDSA using secp256k1 and SHA-256`,
				},
				{
					name:    `EdDSA`,
					value:   `EdDSA`,
					comment: `EdDSA signature algorithms`,
				},
				{
					name:    `PS256`,
					value:   `PS256`,
					comment: `RSASSA-PSS using SHA256 and MGF1-SHA256`,
				},
				{
					name:    `PS384`,
					value:   `PS384`,
					comment: `RSASSA-PSS using SHA384 and MGF1-SHA384`,
				},
				{
					name:    `PS512`,
					value:   `PS512`,
					comment: `RSASSA-PSS using SHA512 and MGF1-SHA512`,
				},
			},
		},
		{
			name:     `KeyEncryptionAlgorithm`,
			comment:  `KeyEncryptionAlgorithm represents the various encryption algorithms as described in https://tools.ietf.org/html/rfc7518#section-4.1`,
			filename: `key_encryption_gen.go`,
			elements: []element{
				{
					name:    `RSA1_5`,
					value:   "RSA1_5",
					comment: `RSA-PKCS1v1.5`,
				},
				{
					name:    `RSA_OAEP`,
					value:   "RSA-OAEP",
					comment: `RSA-OAEP-SHA1`,
				},
				{
					name:    `RSA_OAEP_256`,
					value:   "RSA-OAEP-256",
					comment: `RSA-OAEP-SHA256`,
				},
				{
					name:    `A128KW`,
					value:   "A128KW",
					comment: `AES key wrap (128)`,
				},
				{
					name:    `A192KW`,
					value:   "A192KW",
					comment: `AES key wrap (192)`,
				},
				{
					name:    `A256KW`,
					value:   "A256KW",
					comment: `AES key wrap (256)`,
				},
				{
					name:    `DIRECT`,
					value:   "dir",
					comment: `Direct encryption`,
				},
				{
					name:    `ECDH_ES`,
					value:   "ECDH-ES",
					comment: `ECDH-ES`,
				},
				{
					name:    `ECDH_ES_A128KW`,
					value:   "ECDH-ES+A128KW",
					comment: `ECDH-ES + AES key wrap (128)`,
				},
				{
					name:    `ECDH_ES_A192KW`,
					value:   "ECDH-ES+A192KW",
					comment: `ECDH-ES + AES key wrap (192)`,
				},
				{
					name:    `ECDH_ES_A256KW`,
					value:   "ECDH-ES+A256KW",
					comment: `ECDH-ES + AES key wrap (256)`,
				},
				{
					name:    `A128GCMKW`,
					value:   "A128GCMKW",
					comment: `AES-GCM key wrap (128)`,
				},
				{
					name:    `A192GCMKW`,
					value:   "A192GCMKW",
					comment: `AES-GCM key wrap (192)`,
				},
				{
					name:    `A256GCMKW`,
					value:   "A256GCMKW",
					comment: `AES-GCM key wrap (256)`,
				},
				{
					name:    `PBES2_HS256_A128KW`,
					value:   "PBES2-HS256+A128KW",
					comment: `PBES2 + HMAC-SHA256 + AES key wrap (128)`,
				},
				{
					name:    `PBES2_HS384_A192KW`,
					value:   "PBES2-HS384+A192KW",
					comment: `PBES2 + HMAC-SHA384 + AES key wrap (192)`,
				},
				{
					name:    `PBES2_HS512_A256KW`,
					value:   "PBES2-HS512+A256KW",
					comment: `PBES2 + HMAC-SHA512 + AES key wrap (256)`,
				},
			},
		},
	}

	sort.Slice(typs, func(i, j int) bool {
		return typs[i].name < typs[j].name
	})

	for _, t := range typs {
		t := t
		sort.Slice(t.elements, func(i, j int) bool {
			return t.elements[i].name < t.elements[j].name
		})
		if err := t.Generate(); err != nil {
			return fmt.Errorf(`failed to generate file: %w`, err)
		}
		if err := t.GenerateTest(); err != nil {
			return fmt.Errorf(`failed to generate test file: %w`, err)
		}
	}
	return nil
}

type typ struct {
	name     string
	comment  string
	filename string
	elements []element
}

type element struct {
	name    string
	value   string
	comment string
	invalid bool
}

var isSymmetricKeyEncryption = map[string]struct{}{
	`A128KW`:    {},
	`A192KW`:    {},
	`A256KW`:    {},
	`DIRECT`:    {},
	`A128GCMKW`: {},
	`A192GCMKW`: {},
	`A256GCMKW`: {},

	`PBES2_HS256_A128KW`: {},
	`PBES2_HS384_A192KW`: {},
	`PBES2_HS512_A256KW`: {},
}

func (t typ) Generate() error {
	var buf bytes.Buffer

	o := codegen.NewOutput(&buf)

	o.R("// Code generated by tools/cmd/genjwa/main.go. DO NOT EDIT.")
	o.LL("package jwa")

	o.LL("import (")
	pkgs := []string{
		"fmt",
	}
	for _, pkg := range pkgs {
		o.L("%s", strconv.Quote(pkg))
	}
	o.L(")")

	o.LL("// %s", t.comment)
	o.L("type %s string", t.name)

	o.LL("// Supported values for %s", t.name)
	o.L("const (")
	for _, e := range t.elements {
		o.L("%s %s = %s", e.name, t.name, strconv.Quote(e.value))
		if len(e.comment) > 0 {
			o.R(" // %s", e.comment)
		}
	}
	o.L(")") // end const

	o.L("var all%[1]ss = map[%[1]s]struct{} {", t.name)
	for _, e := range t.elements {
		if !e.invalid {
			o.L("%s: {},", e.name)
		}
	}
	o.L("}")

	o.LL("var list%sOnce sync.Once", t.name)
	o.L("var list%[1]s []%[1]s", t.name)
	o.LL("// %[1]ss returns a list of all available values for %[1]s", t.name)
	o.L("func %[1]ss() []%[1]s {", t.name)
	o.L("list%sOnce.Do(func() {", t.name)
	o.L("list%[1]s = make([]%[1]s, 0, len(all%[1]ss))", t.name)
	o.L("for v := range all%ss {", t.name)
	o.L("list%[1]s = append(list%[1]s, v)", t.name)
	o.L("}")
	o.L("sort.Slice(list%s, func(i, j int) bool {", t.name)
	o.L("return string(list%[1]s[i]) < string(list%[1]s[j])", t.name)
	o.L("})")
	o.L("})")
	o.L("return list%s", t.name)
	o.L("}")

	o.LL("// Accept is used when conversion from values given by")
	o.L("// outside sources (such as JSON payloads) is required")
	o.L("func (v *%s) Accept(value interface{}) error {", t.name)
	o.L("var tmp %s", t.name)
	o.L("if x, ok := value.(%s); ok {", t.name)
	o.L("tmp = x")
	o.L("} else {")
	o.L("var s string")
	o.L("switch x := value.(type) {")
	o.L("case fmt.Stringer:")
	o.L("s = x.String()")
	o.L("case string:")
	o.L("s = x")
	o.L("default:")
	o.L("return fmt.Errorf(`invalid type for jwa.%s: %%T`, value)", t.name)
	o.L("}")
	o.L("tmp = %s(s)", t.name)
	o.L("}")

	o.L("if _, ok := all%ss[tmp]; !ok {", t.name)
	o.L("return fmt.Errorf(`invalid jwa.%s value`)", t.name)
	o.L("}")

	o.LL("*v = tmp")
	o.L("return nil")
	o.L("}") // func (v *%s) Accept(v interface{})

	o.LL("// String returns the string representation of a %s", t.name)
	o.L("func (v %s) String() string {", t.name)
	o.L("return string(v)")
	o.L("}")

	if t.name == "KeyEncryptionAlgorithm" {
		o.LL("// IsSymmetric returns true if the algorithm is a symmetric type")
		o.L("func (v %s) IsSymmetric() bool {", t.name)
		o.L("switch v {")
		o.L("case ")
		var count int
		for _, e := range t.elements {
			if _, ok := isSymmetricKeyEncryption[e.name]; !ok {
				continue
			}
			if count == 0 {
				o.R("%s", e.name)
			} else {
				o.R(",%s", e.name)
			}
			count++
		}
		o.R(":")
		o.L("return true")
		o.L("}")
		o.L("return false")
		o.L("}")
	}

	if err := o.WriteFile(t.filename, codegen.WithFormatCode(true)); err != nil {
		if cfe, ok := err.(codegen.CodeFormatError); ok {
			fmt.Fprint(os.Stderr, cfe.Source())
		}
		return fmt.Errorf(`failed to write to %s: %w`, t.filename, err)
	}
	return nil
}

func (t typ) GenerateTest() error {
	var buf bytes.Buffer

	valids := make([]element, 0, len(t.elements))
	invalids := make([]element, 0, len(t.elements))
	for _, e := range t.elements {
		if e.invalid {
			invalids = append(invalids, e)
			continue
		}
		valids = append(valids, e)
	}

	o := codegen.NewOutput(&buf)
	o.R("// Code generated by tools/cmd/genjwa/main.go. DO NOT EDIT")
	o.LL("package jwa_test")

	o.L("import (")
	pkgs := []string{
		"testing",
		"github.com/lestrrat-go/jwx/v2/jwa",
		"github.com/stretchr/testify/assert",
	}
	for _, pkg := range pkgs {
		o.L("%s", strconv.Quote(pkg))
	}
	o.L(")")

	o.LL("func Test%s(t *testing.T) {", t.name)
	o.L("t.Parallel()")
	for _, e := range valids {
		o.L("t.Run(`accept jwa constant %s`, func(t *testing.T) {", e.name)
		o.L("t.Parallel()")
		o.L("var dst jwa.%s", t.name)
		o.L("if !assert.NoError(t, dst.Accept(jwa.%s), `accept is successful`) {", e.name)
		o.L("return")
		o.L("}")
		o.L("if !assert.Equal(t, jwa.%s, dst, `accepted value should be equal to constant`) {", e.name)
		o.L("return")
		o.L("}")
		o.L("})")

		o.L("t.Run(`accept the string %s`, func(t *testing.T) {", e.value)
		o.L("t.Parallel()")
		o.L("var dst jwa.%s", t.name)
		o.L("if !assert.NoError(t, dst.Accept(%#v), `accept is successful`) {", e.value)
		o.L("return")
		o.L("}")
		o.L("if !assert.Equal(t, jwa.%s, dst, `accepted value should be equal to constant`) {", e.name)
		o.L("return")
		o.L("}")
		o.L("})")

		o.L("t.Run(`accept fmt.Stringer for %s`, func(t *testing.T) {", e.value)
		o.L("t.Parallel()")
		o.L("var dst jwa.%s", t.name)
		o.L("if !assert.NoError(t, dst.Accept(stringer{ src: %#v }), `accept is successful`) {", e.value)
		o.L("return")
		o.L("}")
		o.L("if !assert.Equal(t, jwa.%s, dst, `accepted value should be equal to constant`) {", e.name)
		o.L("return")
		o.L("}")
		o.L("})")

		o.L("t.Run(`stringification for %s`, func(t *testing.T) {", e.value)
		o.L("t.Parallel()")
		o.L("if !assert.Equal(t, %#v, jwa.%s.String(), `stringified value matches`) {", e.value, e.name)
		o.L("return")
		o.L("}")
		o.L("})")
	}

	for _, e := range invalids {
		o.L("t.Run(`do not accept invalid constant %s`, func(t *testing.T) {", e.name)
		o.L("t.Parallel()")
		o.L("var dst jwa.%s", t.name)
		o.L("if !assert.Error(t, dst.Accept(jwa.%s), `accept should fail`) {", e.name)
		o.L("return")
		o.L("}")
		o.L("})")
	}

	o.L("t.Run(`bail out on random integer value`, func(t *testing.T) {")
	o.L("t.Parallel()")
	o.L("var dst jwa.%s", t.name)
	o.L("if !assert.Error(t, dst.Accept(1), `accept should fail`) {")
	o.L("return")
	o.L("}")
	o.L("})")

	o.L("t.Run(`do not accept invalid (totally made up) string value`, func(t *testing.T) {")
	o.L("t.Parallel()")
	o.L("var dst jwa.%s", t.name)
	o.L("if !assert.Error(t, dst.Accept(`totallyInvfalidValue`), `accept should fail`) {")
	o.L("return")
	o.L("}")
	o.L("})")

	if t.name == "KeyEncryptionAlgorithm" {
		o.L("t.Run(`check symmetric values`, func(t *testing.T) {")
		o.L("t.Parallel()")
		for _, e := range t.elements {
			o.L("t.Run(`%s`, func(t *testing.T) {", e.name)
			if _, ok := isSymmetricKeyEncryption[e.name]; ok {
				o.L("assert.True(t, jwa.%[1]s.IsSymmetric(), `jwa.%[1]s should be symmetric`)", e.name)
			} else {
				o.L("assert.False(t, jwa.%[1]s.IsSymmetric(), `jwa.%[1]s should NOT be symmetric`)", e.name)
			}
			o.L("})")
		}
		o.L("})")
	}

	o.L("t.Run(`check list of elements`, func(t *testing.T) {")
	o.L("t.Parallel()")
	o.L("var expected = map[jwa.%s]struct{} {", t.name)
	for _, e := range t.elements {
		if !e.invalid {
			o.L("jwa.%s: {},", e.name)
		}
	}
	o.L("}")
	o.L("for _, v := range jwa.%ss() {", t.name)
	if t.name == "EllipticCurveAlgorithm" {
		o.L("// There is no good way to detect from a test if es256k (secp256k1)")
		o.L("// is supported, so just allow it")
		o.L("if v.String() == `secp256k1` {")
		o.L("continue")
		o.L("}")
	}
	o.L("if _, ok := expected[v]; !assert.True(t, ok, `%%s should be in the expected list`, v) {")
	o.L("return")
	o.L("}")
	o.L("delete(expected, v)")
	o.L("}")
	o.L("if !assert.Len(t, expected, 0) {")
	o.L("return")
	o.L("}")
	o.L("})")

	o.L("}")

	filename := strings.Replace(t.filename, "_gen.go", "_gen_test.go", 1)
	if err := o.WriteFile(filename, codegen.WithFormatCode(true)); err != nil {
		if cfe, ok := err.(codegen.CodeFormatError); ok {
			fmt.Fprint(os.Stderr, cfe.Source())
		}
		return fmt.Errorf(`failed to write to %s: %w`, filename, err)
	}
	return nil
}
