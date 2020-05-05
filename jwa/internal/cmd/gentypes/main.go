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
			},
		},
		{
			name:     `EllipticCurveAlgorithm`,
			comment:  ` EllipticCurveAlgorithm represents the algorithms used for EC keys`,
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
			return errors.Wrap(err, `failed to generate file`)
		}
		if err := t.GenerateTest(); err != nil {
			return errors.Wrap(err, `failed to generate test file`)
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

func (t typ) Generate() error {
	var buf bytes.Buffer

	fmt.Fprintf(&buf, "// this file was auto-generated by internal/cmd/gentypes/main.go: DO NOT EDIT")
	fmt.Fprintf(&buf, "\n\npackage jwa")

	fmt.Fprintf(&buf, "\n\nimport (")
	pkgs := []string{
		"fmt",
		"github.com/pkg/errors",
	}
	for _, pkg := range pkgs {
		fmt.Fprintf(&buf, "\n%s", strconv.Quote(pkg))
	}
	fmt.Fprintf(&buf, "\n)")

	fmt.Fprintf(&buf, "\n\n// %s", t.comment)
	fmt.Fprintf(&buf, "\ntype %s string", t.name)

	fmt.Fprintf(&buf, "\n\n// Supported values for %s", t.name)
	fmt.Fprintf(&buf, "\nconst (")
	for _, e := range t.elements {
		fmt.Fprintf(&buf, "\n%s %s = %s", e.name, t.name, strconv.Quote(e.value))
		if len(e.comment) > 0 {
			fmt.Fprintf(&buf, " // %s", e.comment)
		}
	}
	fmt.Fprintf(&buf, "\n)") // end const

	fmt.Fprintf(&buf, "\n\n// Accept is used when conversion from values given by")
	fmt.Fprintf(&buf, "\n// outside sources (such as JSON payloads) is required")
	fmt.Fprintf(&buf, "\nfunc (v *%s) Accept(value interface{}) error {", t.name)
	fmt.Fprintf(&buf, "\nvar tmp %s", t.name)
	fmt.Fprintf(&buf, "\nif x, ok := value.(%s); ok {", t.name)
	fmt.Fprintf(&buf, "\ntmp = x")
	fmt.Fprintf(&buf, "\n} else {")
	fmt.Fprintf(&buf, "\nvar s string")
	fmt.Fprintf(&buf, "\nswitch x := value.(type) {")
	fmt.Fprintf(&buf, "\ncase fmt.Stringer:")
	fmt.Fprintf(&buf, "\ns = x.String()")
	fmt.Fprintf(&buf, "\ncase string:")
	fmt.Fprintf(&buf, "\ns = x")
	fmt.Fprintf(&buf, "\ndefault:")
	fmt.Fprintf(&buf, "\nreturn errors.Errorf(`invalid type for jwa.%s: %%T`, value)", t.name)
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\ntmp = %s(s)", t.name)
	fmt.Fprintf(&buf, "\n}")

	fmt.Fprintf(&buf, "\nswitch tmp {")
	fmt.Fprintf(&buf, "\ncase ")
	valids := make([]element, 0, len(t.elements))
	for _, e := range t.elements {
		if e.invalid {
			continue
		}
		valids = append(valids, e)
	}

	for i, e := range valids {
		fmt.Fprintf(&buf, "%s", e.name)
		if i < len(valids)-1 {
			fmt.Fprintf(&buf, ", ")
		}
	}
	fmt.Fprintf(&buf, ":")
	fmt.Fprintf(&buf, "\ndefault:")
	fmt.Fprintf(&buf, "\nreturn errors.Errorf(`invalid jwa.%s value`)", t.name)
	fmt.Fprintf(&buf, "\n}")

	fmt.Fprintf(&buf, "\n\n*v = tmp")
	fmt.Fprintf(&buf, "\nreturn nil")
	fmt.Fprintf(&buf, "\n}") // func (v *%s) Accept(v interface{})

	fmt.Fprintf(&buf, "\n\n// String returns the string representation of a %s", t.name)
	fmt.Fprintf(&buf, "\nfunc (v %s) String() string {", t.name)
	fmt.Fprintf(&buf, "\nreturn string(v)")
	fmt.Fprintf(&buf, "\n}")

	formatted, err := imports.Process("", buf.Bytes(), nil)
	if err != nil {
		os.Stdout.Write(buf.Bytes())
		return errors.Wrap(err, `failed to format source`)
	}

	f, err := os.Create(t.filename)
	if err != nil {
		return errors.Wrapf(err, `failed to create %s`, t.filename)
	}
	defer f.Close()
	f.Write(formatted)

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

	fmt.Fprintf(&buf, "// this file was auto-generated by internal/cmd/gentypes/main.go: DO NOT EDIT")
	fmt.Fprintf(&buf, "\n\npackage jwa_test")

	fmt.Fprintf(&buf, "\nimport (")
	pkgs := []string{
		"testing",
		"github.com/lestrrat-go/jwx/jwa",
		"github.com/stretchr/testify/assert",
	}
	for _, pkg := range pkgs {
		fmt.Fprintf(&buf, "\n%s", strconv.Quote(pkg))
	}
	fmt.Fprintf(&buf, "\n)")

	fmt.Fprintf(&buf, "\n\nfunc Test%s(t *testing.T) {", t.name)
	for _, e := range valids {
		fmt.Fprintf(&buf, "\nt.Run(`accept jwa constant %s`, func(t *testing.T) {", e.name)
		fmt.Fprintf(&buf, "\nt.Parallel()")
		fmt.Fprintf(&buf, "\nvar dst jwa.%s", t.name)
		fmt.Fprintf(&buf, "\nif !assert.NoError(t, dst.Accept(jwa.%s), `accept is successful`) {", e.name)
		fmt.Fprintf(&buf, "\nreturn")
		fmt.Fprintf(&buf, "\n}")
		fmt.Fprintf(&buf, "\nif !assert.Equal(t, jwa.%s, dst, `accepted value should be equal to constant`) {", e.name)
		fmt.Fprintf(&buf, "\nreturn")
		fmt.Fprintf(&buf, "\n}")
		fmt.Fprintf(&buf, "\n})")

		fmt.Fprintf(&buf, "\nt.Run(`accept the string %s`, func(t *testing.T) {", e.value)
		fmt.Fprintf(&buf, "\nt.Parallel()")
		fmt.Fprintf(&buf, "\nvar dst jwa.%s", t.name)
		fmt.Fprintf(&buf, "\nif !assert.NoError(t, dst.Accept(%#v), `accept is successful`) {", e.value)
		fmt.Fprintf(&buf, "\nreturn")
		fmt.Fprintf(&buf, "\n}")
		fmt.Fprintf(&buf, "\nif !assert.Equal(t, jwa.%s, dst, `accepted value should be equal to constant`) {", e.name)
		fmt.Fprintf(&buf, "\nreturn")
		fmt.Fprintf(&buf, "\n}")
		fmt.Fprintf(&buf, "\n})")

		fmt.Fprintf(&buf, "\nt.Run(`accept fmt.Stringer for %s`, func(t *testing.T) {", e.value)
		fmt.Fprintf(&buf, "\nt.Parallel()")
		fmt.Fprintf(&buf, "\nvar dst jwa.%s", t.name)
		fmt.Fprintf(&buf, "\nif !assert.NoError(t, dst.Accept(stringer{ src: %#v }), `accept is successful`) {", e.value)
		fmt.Fprintf(&buf, "\nreturn")
		fmt.Fprintf(&buf, "\n}")
		fmt.Fprintf(&buf, "\nif !assert.Equal(t, jwa.%s, dst, `accepted value should be equal to constant`) {", e.name)
		fmt.Fprintf(&buf, "\nreturn")
		fmt.Fprintf(&buf, "\n}")
		fmt.Fprintf(&buf, "\n})")

		fmt.Fprintf(&buf, "\nt.Run(`stringification for %s`, func(t *testing.T) {", e.value)
		fmt.Fprintf(&buf, "\nt.Parallel()")
		fmt.Fprintf(&buf, "\nif !assert.Equal(t, %#v, jwa.%s.String(), `stringified value matches`) {", e.value, e.name)
		fmt.Fprintf(&buf, "\nreturn")
		fmt.Fprintf(&buf, "\n}")
		fmt.Fprintf(&buf, "\n})")
	}

	for _, e := range invalids {
		fmt.Fprintf(&buf, "\nt.Run(`do not accept invalid constant %s`, func(t *testing.T) {", e.name)
		fmt.Fprintf(&buf, "\nt.Parallel()")
		fmt.Fprintf(&buf, "\nvar dst jwa.%s", t.name)
		fmt.Fprintf(&buf, "\nif !assert.Error(t, dst.Accept(jwa.%s), `accept should fail`) {", e.name)
		fmt.Fprintf(&buf, "\nreturn")
		fmt.Fprintf(&buf, "\n}")
		fmt.Fprintf(&buf, "\n})")
	}

	fmt.Fprintf(&buf, "\nt.Run(`bail out on random integer value`, func(t *testing.T) {")
	fmt.Fprintf(&buf, "\nt.Parallel()")
	fmt.Fprintf(&buf, "\nvar dst jwa.%s", t.name)
	fmt.Fprintf(&buf, "\nif !assert.Error(t, dst.Accept(1), `accept should fail`) {")
	fmt.Fprintf(&buf, "\nreturn")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\n})")

	fmt.Fprintf(&buf, "\nt.Run(`do not accept invalid (totally made up) string value`, func(t *testing.T) {")
	fmt.Fprintf(&buf, "\nt.Parallel()")
	fmt.Fprintf(&buf, "\nvar dst jwa.%s", t.name)
	fmt.Fprintf(&buf, "\nif !assert.Error(t, dst.Accept(`totallyInvfalidValue`), `accept should fail`) {")
	fmt.Fprintf(&buf, "\nreturn")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\n})")

	fmt.Fprintf(&buf, "\n}")

	formatted, err := imports.Process("", buf.Bytes(), nil)
	if err != nil {
		os.Stdout.Write(buf.Bytes())
		return errors.Wrap(err, `failed to format source`)
	}

	filename := strings.Replace(t.filename, "_gen.go", "_gen_test.go", 1)
	f, err := os.Create(filename)
	if err != nil {
		return errors.Wrapf(err, `failed to create %s`, t.filename)
	}
	defer f.Close()
	f.Write(formatted)

	return nil
}
