package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode"

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
			name:      `SignatureAlgorithm`,
			comment:   `SignatureAlgorithm represents the various signature algorithms as described in https://tools.ietf.org/html/rfc7518#section-3.1`,
			filename:  `signature_gen.go`,
			symmetric: true,
			elements: []element{
				{
					name:  `NoSignature`,
					value: "none",
				},
				{
					name:    `HS256`,
					value:   "HS256",
					comment: `HMAC using SHA-256`,
					sym:     true,
				},
				{
					name:    `HS384`,
					value:   `HS384`,
					comment: `HMAC using SHA-384`,
					sym:     true,
				},
				{
					name:    `HS512`,
					value:   "HS512",
					comment: `HMAC using SHA-512`,
					sym:     true,
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
			name:      `KeyEncryptionAlgorithm`,
			comment:   `KeyEncryptionAlgorithm represents the various encryption algorithms as described in https://tools.ietf.org/html/rfc7518#section-4.1`,
			filename:  `key_encryption_gen.go`,
			symmetric: true,
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
					name:    `RSA_OAEP_384`,
					value:   "RSA-OAEP-384",
					comment: `RSA-OAEP-SHA384`,
				},
				{
					name:    `RSA_OAEP_512`,
					value:   "RSA-OAEP-512",
					comment: `RSA-OAEP-SHA512`,
				},
				{
					name:    `A128KW`,
					value:   "A128KW",
					comment: `AES key wrap (128)`,
					sym:     true,
				},
				{
					name:    `A192KW`,
					value:   "A192KW",
					comment: `AES key wrap (192)`,
					sym:     true,
				},
				{
					name:    `A256KW`,
					value:   "A256KW",
					comment: `AES key wrap (256)`,
					sym:     true,
				},
				{
					name:    `DIRECT`,
					value:   "dir",
					comment: `Direct encryption`,
					sym:     true,
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
					sym:     true,
				},
				{
					name:    `A192GCMKW`,
					value:   "A192GCMKW",
					comment: `AES-GCM key wrap (192)`,
					sym:     true,
				},
				{
					name:    `A256GCMKW`,
					value:   "A256GCMKW",
					comment: `AES-GCM key wrap (256)`,
					sym:     true,
				},
				{
					name:    `PBES2_HS256_A128KW`,
					value:   "PBES2-HS256+A128KW",
					comment: `PBES2 + HMAC-SHA256 + AES key wrap (128)`,
					sym:     true,
				},
				{
					name:    `PBES2_HS384_A192KW`,
					value:   "PBES2-HS384+A192KW",
					comment: `PBES2 + HMAC-SHA384 + AES key wrap (192)`,
					sym:     true,
				},
				{
					name:    `PBES2_HS512_A256KW`,
					value:   "PBES2-HS512+A256KW",
					comment: `PBES2 + HMAC-SHA512 + AES key wrap (256)`,
					sym:     true,
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
	name      string
	comment   string
	filename  string
	elements  []element
	symmetric bool
}

type element struct {
	name    string
	value   string
	comment string
	invalid bool
	sym     bool
}

func (t typ) Generate() error {
	var buf bytes.Buffer

	o := codegen.NewOutput(&buf)

	o.R("// Code generated by tools/cmd/genjwa/main.go. DO NOT EDIT.")
	o.LL("package jwa")

	o.LL("import (")
	pkgs := []string{
		"fmt",
		"sort",
		"sync",
		"strings",
	}
	for _, pkg := range pkgs {
		o.L("%s", strconv.Quote(pkg))
	}
	o.L(")")

	o.LL("var muAll%s sync.RWMutex", t.name)
	o.L("var all%[1]s = map[string]%[1]s{}", t.name)
	o.L("var muList%s sync.RWMutex", t.name)
	o.L("var list%s []%s", t.name, t.name)
	o.L("var builtin%s = map[string]struct{}{}", t.name)

	o.LL("func init() {")
	o.L("// builtin values for %s", t.name)
	o.L("algorithms := make([]%s, 0, %d)", t.name, len(t.elements))
	if t.symmetric {
		o.L("for _, alg := range []string{")
		ecount := 0
		for _, e := range t.elements {
			if !e.sym {
				continue
			}
			if ecount > 0 {
				o.R(", ")
			}
			ecount++
			o.R("%q", e.value)
		}
		o.R("} {")
		o.L("algorithms = append(algorithms, New%s(alg, WithIsSymmetric(true)))", t.name)
		o.L("}")
	}

	o.LL("for _, alg := range []string{")
	ecount := 0
	for _, e := range t.elements {
		if e.sym {
			continue
		}
		if e.invalid {
			continue
		}
		if ecount > 0 {
			o.R(", ")
		}
		ecount++
		o.R("%q", e.value)
	}
	o.R("} {")
	o.L("algorithms = append(algorithms, New%s(alg))", t.name)
	o.L("}")

	o.LL("Register%s(algorithms...)", t.name)
	o.L("}") // end init

	// Accessors for builtin algorithms
	for _, e := range t.elements {
		if e.invalid {
			o.L("var %s = New%s(%q)", fmt.Sprintf("%c%s", unicode.ToLower(rune(e.name[0])), e.name[1:]), t.name, e.value)
		}
		o.LL("// %s returns the %s algorithm object.", e.name, e.name)
		o.L("func %s() %s {", e.name, t.name)
		if e.invalid {
			o.L("return %s", fmt.Sprintf("%c%s", unicode.ToLower(rune(e.name[0])), e.name[1:]))
		} else {
			o.L("return lookupBuiltin%s(%q)", t.name, e.value)
		}
		o.L("}")
	}

	o.LL("func lookupBuiltin%s(name string) %s {", t.name, t.name)
	o.L("muAll%s.RLock()", t.name)
	o.L("v, ok := all%s[name]", t.name)
	o.L("muAll%s.RUnlock()", t.name)
	o.L("if !ok {")
	o.L("panic(fmt.Sprintf(`jwa: %s %%q not registered`, name))", t.name)
	o.L("}")
	o.L("return v")
	o.L("}")

	o.LL("type %s struct {", t.name)
	o.L("name string")
	if t.symmetric {
		o.L("isSymmetric bool")
	}
	o.L("}")

	o.LL("func (s %s) String() string {", t.name)
	o.L("return s.name")
	o.L("}")

	if t.symmetric {
		o.LL("func (s %s) IsSymmetric() bool {", t.name)
		o.L("return s.isSymmetric")
		o.L("}")
	}

	o.LL("// Empty%[1]s returns an empty %[1]s object, used as a zero value", t.name)
	o.L("func Empty%s() %s {", t.name, t.name)
	o.L("return %s{}", t.name)
	o.L("}")

	o.LL("// New%[1]s creates a new %[1]s object", t.name)
	o.L("func New%[1]s(name string, options ...NewKeyAlgorithmOption) %[1]s {", t.name)
	if !t.symmetric {
		o.L("return %s{name: name}", t.name)
	} else {
		o.L("var isSymmetric bool")
		o.L("//nolint:forcetypeassert")
		o.L("for _, option := range options {")
		o.L("switch option.Ident() {")
		o.L("case identSymmetricAlgorithm{}:")
		o.L("isSymmetric = option.Value().(bool)")
		o.L("}")
		o.L("}")
		o.L("return %s{name: name, isSymmetric: isSymmetric}", t.name)
	}
	o.L("}")

	o.LL("// Lookup%[1]s returns the %[1]s object for the given name", t.name)
	o.L("func Lookup%[1]s(name string) (%[1]s, bool) {", t.name)
	o.L("muAll%[1]s.RLock()", t.name)
	o.L("v, ok := all%[1]s[name]", t.name)
	o.L("muAll%[1]s.RUnlock()", t.name)
	o.L("return v, ok")
	o.L("}")

	o.LL("// Register%[1]s registers a new %[1]s. The signature value must be immutable", t.name)
	o.L("// and safe to be used by multiple goroutines, as it is going to be shared with all other users of this library")
	o.L("func Register%[1]s(algorithms ...%[1]s) {", t.name)
	o.L("muAll%[1]s.Lock()", t.name)
	o.L("for _, alg := range algorithms {")
	o.L("all%[1]s[alg.String()] = alg", t.name)
	o.L("}")
	o.L("muAll%[1]s.Unlock()", t.name)
	o.L("rebuild%[1]s()", t.name)
	o.L("}")

	o.LL("// Unregister%[1]s unregisters a %[1]s from its known database.", t.name)
	o.L("// Non-existent entries, as well as built-in algorithms will silently be ignored")
	o.L("func Unregister%[1]s(algorithms ...%[1]s) {", t.name)
	o.L("muAll%[1]s.Lock()", t.name)
	o.L("for _, alg := range algorithms {")
	o.L("if _, ok := builtin%[1]s[alg.String()]; ok {", t.name)
	o.L("continue")
	o.L("}")
	o.L("delete(all%[1]s, alg.String())", t.name)
	o.L("}")
	o.L("muAll%[1]s.Unlock()", t.name)
	o.L("rebuild%[1]s()", t.name)
	o.L("}")

	o.LL("func rebuild%[1]s() {", t.name)
	o.L("list := make([]%[1]s, 0, len(all%[1]s))", t.name)
	o.L("muAll%[1]s.RLock()", t.name)
	o.L("for _, v := range all%[1]s {", t.name)
	o.L("list = append(list, v)")
	o.L("}")
	o.L("muAll%[1]s.RUnlock()", t.name)
	o.L("sort.Slice(list, func(i, j int) bool {")
	o.L("return list[i].String() < list[j].String()")
	o.L("})")
	o.L("muList%[1]s.Lock()", t.name)
	o.L("list%[1]s = list", t.name)
	o.L("muList%[1]s.Unlock()", t.name)
	o.L("}")

	o.LL("// %[1]ss returns a list of all available values for %[1]s", t.name)
	o.L("func %[1]ss() []%[1]s {", t.name)
	o.L("muList%[1]s.RLock()", t.name)
	o.L("defer muList%[1]s.RUnlock()", t.name)
	o.L("return list%[1]s", t.name)
	o.L("}")

	o.LL("// MarshalJSON serializes the %[1]s object to a JSON string", t.name)
	o.L("func (s %[1]s) MarshalJSON() ([]byte, error) {", t.name)
	o.L("return json.Marshal(s.String())")
	o.L("}")

	o.LL("// UnmarshalJSON deserializes the JSON string to a %[1]s object", t.name)
	o.L("func (s *%[1]s) UnmarshalJSON(data []byte) error {", t.name)
	o.L("var name string")
	o.L("if err := json.Unmarshal(data, &name); err != nil {")
	o.L("return fmt.Errorf(`failed to unmarshal %[1]s: %%w`, err)", t.name)
	o.L("}")
	o.L("v, ok := Lookup%[1]s(name)", t.name)
	o.L("if !ok {")
	o.L("return fmt.Errorf(`unknown %[1]s: %%s`, name)", t.name)
	o.L("}")
	o.L("*s = v")
	o.L("return nil")
	o.L("}")

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
		"strconv",
		"testing",
		"github.com/lestrrat-go/jwx/v3/jwa",
		"github.com/stretchr/testify/require",
	}
	for _, pkg := range pkgs {
		o.L("%s", strconv.Quote(pkg))
	}
	o.L(")")

	o.LL("func Test%s(t *testing.T) {", t.name)
	o.L("t.Parallel()")
	for _, e := range valids {
		o.L("t.Run(`Lookup the object`, func(t *testing.T) {")
		o.L("t.Parallel()")
		o.L("v, ok := jwa.Lookup%s(%q)", t.name, e.value)
		o.L("require.True(t, ok, `Lookup should succeed`)")
		o.L("require.Equal(t, jwa.%s(), v, `Lookup value should be equal to constant`)", e.name)
		o.L("})")

		o.L("t.Run(`Unmarshal the string %s`, func(t *testing.T) {", e.value)
		o.L("t.Parallel()")
		o.L("var dst jwa.%s", t.name)
		o.L("require.NoError(t, json.Unmarshal([]byte(strconv.Quote(%q)), &dst), `UnmarshalJSON is successful`)", e.value)
		o.L("require.Equal(t, jwa.%s(), dst, `unmarshaled value should be equal to constant`)", e.name)
		o.L("})")

		o.L("t.Run(`stringification for %s`, func(t *testing.T) {", e.value)
		o.L("t.Parallel()")
		o.L("require.Equal(t, %#v, jwa.%s().String(), `stringified value matches`)", e.value, e.name)
		o.L("})")
	}

	o.L("t.Run(`Unmarshal should fail for invalid value (totally made up) string value`, func(t *testing.T) {")
	o.L("t.Parallel()")
	o.L("var dst jwa.%s", t.name)
	o.L("require.Error(t, json.Unmarshal([]byte(`totallyInvalidValue`), &dst), `Unmarshal should fail`)")
	o.L("})")

	if t.symmetric {
		o.L("t.Run(`check symmetric values`, func(t *testing.T) {")
		o.L("t.Parallel()")
		for _, e := range t.elements {
			o.L("t.Run(`%s`, func(t *testing.T) {", e.name)
			if e.sym {
				o.L("require.True")
			} else {
				o.L("require.False")
			}
			o.R("(t, jwa.%[1]s().IsSymmetric(), `jwa.%[1]s returns expected value`)", e.name)
			o.L("})")
		}
		o.L("})")
	}

	o.L("t.Run(`check list of elements`, func(t *testing.T) {")
	o.L("t.Parallel()")
	o.L("var expected = map[jwa.%s]struct{} {", t.name)
	for _, e := range t.elements {
		if !e.invalid {
			o.L("jwa.%s(): {},", e.name)
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
	o.L("_, ok := expected[v]")
	o.L("require.True(t, ok, `%%s should be in the expected list`, v)")
	o.L("delete(expected, v)")
	o.L("}")
	o.L("require.Len(t, expected, 0)")
	o.L("})")
	o.L("}")

	o.LL("// Note: this test can NOT be run in parallel as it uses options with global effect.")
	o.L("func Test%sCustomAlgorithm(t *testing.T) {", t.name)
	o.L("// These subtests can NOT be run in parallel as options with global effect change.")
	o.L("const customAlgorithmValue = `custom-algorithm`")
	if t.symmetric {
		o.L("for _, symmetric := range []bool{true, false} {")
	}
	o.L(`customAlgorithm := jwa.New%[1]s(customAlgorithmValue`, t.name)
	if t.symmetric {
		o.R(`, jwa.WithIsSymmetric(symmetric))`)
	} else {
		o.R(`)`)
	}
	o.L("// Unregister the custom algorithm, in case tests fail.")
	o.L("t.Cleanup(func() {")
	o.L("jwa.Unregister%[1]s(customAlgorithm)", t.name)
	o.L("})")
	o.L("t.Run(`with custom algorithm registered`, func(t *testing.T) {")
	o.L("jwa.Register%[1]s(customAlgorithm)", t.name)
	o.L("t.Run(`Lookup the object`, func(t *testing.T) {")
	o.L("t.Parallel()")
	o.L("v, ok := jwa.Lookup%[1]s(customAlgorithmValue)", t.name)
	o.L("require.True(t, ok, `Lookup should succeed`)")
	o.L("require.Equal(t, customAlgorithm, v, `Lookup value should be equal to constant`)")
	o.L("})")
	o.L("t.Run(`Unmarshal custom algorithm`, func(t *testing.T) {")
	o.L("t.Parallel()")
	o.L("var dst jwa.%[1]s", t.name)
	o.L("require.NoError(t, json.Unmarshal([]byte(strconv.Quote(customAlgorithmValue)), &dst), `Unmarshal is successful`)")
	o.L("require.Equal(t, customAlgorithm, dst, `accepted value should be equal to variable`)")
	o.L("})")
	if t.symmetric {
		o.L("t.Run(`check symmetric`, func(t *testing.T) {")
		o.L("t.Parallel()")
		o.L("require.Equal(t, symmetric, customAlgorithm.IsSymmetric(), `custom algorithm's symmetric attribute should match`)")
		o.L("})")
	}
	o.L("})")
	o.L("t.Run(`with custom algorithm deregistered`, func(t *testing.T) {")
	o.L("jwa.Unregister%[1]s(customAlgorithm)", t.name)
	o.L("t.Run(`Lookup the object`, func(t *testing.T) {")
	o.L("t.Parallel()")
	o.L("_, ok := jwa.Lookup%[1]s(customAlgorithmValue)", t.name)
	o.L("require.False(t, ok, `Lookup should fail`)")
	o.L("})")
	o.L("t.Run(`Unmarshal custom algorithm`, func(t *testing.T) {")
	o.L("t.Parallel()")
	o.L("var dst jwa.%[1]s", t.name)
	o.L("require.Error(t, json.Unmarshal([]byte(customAlgorithmValue), &dst), `Unmarshal should fail`)")
	o.L("})")
	o.L("})")
	if t.symmetric {
		o.L("}") // ending the for _, symmetric := range loop
	}
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
