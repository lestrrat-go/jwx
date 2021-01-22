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
	"github.com/pkg/errors"
)

const (
	agreementPartyUInfo = "agreementPartyUInfo"
	agreementPartyVInfo = "agreementPartyVInfo"
	ephemeralPublicKey  = "ephemeralPublicKey"
	jwkKey              = "jwk"
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
	if strings.HasPrefix(s, "jwa.") && strings.HasSuffix(s, "Algorithm") {
		s = "string"
	}

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
	return !(s == "jwk.Key" || s == "jwk.ECDSAPublicKey" || strings.HasPrefix(s, `*`) || strings.HasPrefix(s, `[]`))
}

func generateHeaders() error {
	fields := []headerField{
		{
			name:   `agreementPartyUInfo`,
			method: `AgreementPartyUInfo`,
			typ:    `[]byte`,
			key:    `apu`,
			//			comment:   `https://tools.ietf.org/html/rfc7515#section-4.1.1`,
			jsonTag: "`" + `json:"apu,omitempty"` + "`",
		},
		{
			name:   `agreementPartyVInfo`,
			method: `AgreementPartyVInfo`,
			typ:    `[]byte`,
			key:    `apv`,
			//			comment:   `https://tools.ietf.org/html/rfc7515#section-4.1.1`,
			jsonTag: "`" + `json:"apv,omitempty"` + "`",
		},
		{
			name:   `algorithm`,
			method: `Algorithm`,
			typ:    `jwa.KeyEncryptionAlgorithm`,
			key:    `alg`,
			//			comment:   `https://tools.ietf.org/html/rfc7515#section-4.1.1`,
			jsonTag: "`" + `json:"alg,omitempty"` + "`",
		},
		{
			name:   `compression`,
			method: `Compression`,
			typ:    `jwa.CompressionAlgorithm`,
			key:    `zip`,
			//			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.11`,
			jsonTag: "`" + `json:"zip,omitempty"` + "`",
		},
		{
			name:   `contentEncryption`,
			method: `ContentEncryption`,
			typ:    `jwa.ContentEncryptionAlgorithm`,
			key:    `enc`,
			//			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.11`,
			jsonTag: "`" + `json:"enc,omitempty"` + "`",
		},
		{
			name:   `contentType`,
			method: `ContentType`,
			typ:    `string`,
			key:    `cty`,
			//			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.10`,
			jsonTag: "`" + `json:"cty,omitempty"` + "`",
		},
		{
			name:   `critical`,
			method: `Critical`,
			typ:    `[]string`,
			key:    `crit`,
			//			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.11`,
			jsonTag: "`" + `json:"crit,omitempty"` + "`",
		},
		{
			name:   `ephemeralPublicKey`,
			method: `EphemeralPublicKey`,
			typ:    `jwk.Key`,
			key:    `epk`,
			//			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.3`,
			jsonTag: "`" + `json:"epk,omitempty"` + "`",
		},
		{
			name:   `jwk`,
			method: `JWK`,
			typ:    `jwk.Key`,
			key:    `jwk`,
			//			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.3`,
			jsonTag: "`" + `json:"jwk,omitempty"` + "`",
		},
		{
			name:   `jwkSetURL`,
			method: `JWKSetURL`,
			typ:    `string`,
			key:    `jku`,
			//			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.2`,
			jsonTag: "`" + `json:"jku,omitempty"` + "`",
		},
		{
			name:   `keyID`,
			method: `KeyID`,
			typ:    `string`,
			key:    `kid`,
			//			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.4`,
			jsonTag: "`" + `json:"kid,omitempty"` + "`",
		},
		{
			name:   `typ`,
			method: `Type`,
			typ:    `string`,
			key:    `typ`,
			//			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.9`,
			jsonTag: "`" + `json:"typ,omitempty"` + "`",
		},
		{
			name:   `x509CertChain`,
			method: `X509CertChain`,
			typ:    `[]string`,
			key:    `x5c`,
			//			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.6`,
			jsonTag: "`" + `json:"x5c,omitempty"` + "`",
		},
		{
			name:   `x509CertThumbprint`,
			method: `X509CertThumbprint`,
			typ:    `string`,
			key:    `x5t`,
			//			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.7`,
			jsonTag: "`" + `json:"x5t,omitempty"` + "`",
		},
		{
			name:   `x509CertThumbprintS256`,
			method: `X509CertThumbprintS256`,
			typ:    `string`,
			key:    `x5t#S256`,
			//			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.8`,
			jsonTag: "`" + `json:"x5t#S256,omitempty"` + "`",
		},
		{
			name:   `x509URL`,
			method: `X509URL`,
			typ:    `string`,
			key:    `x5u`,
			//			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.5`,
			jsonTag: "`" + `json:"x5u,omitempty"` + "`",
		},
	}

	sort.Slice(fields, func(i, j int) bool {
		return fields[i].name < fields[j].name
	})

	var buf bytes.Buffer

	fmt.Fprintf(&buf, "\n// This file is auto-generated by internal/cmd/genheaders/main.go. DO NOT EDIT")
	fmt.Fprintf(&buf, "\n\npackage jwe")

	fmt.Fprintf(&buf, "\n\nimport (")
	pkgs := []string{
		"bytes",
		"context",
		"github.com/lestrrat-go/jwx/internal/json",
		"fmt",
		"sort",
		"strconv",
		"sync",
		"github.com/lestrrat-go/jwx/buffer",
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
		fmt.Fprintf(&buf, "\n%s() %s", f.method, f.typ) //PointerElem())
	}

	// These are used to iterate through all keys in a header
	fmt.Fprintf(&buf, "\nIterate(ctx context.Context) Iterator")
	fmt.Fprintf(&buf, "\nWalk(ctx context.Context, v Visitor) error")
	fmt.Fprintf(&buf, "\nAsMap(ctx context.Context) (map[string]interface{}, error)")

	// These are used to access a single element by key name
	fmt.Fprintf(&buf, "\nGet(string) (interface{}, bool)")
	fmt.Fprintf(&buf, "\nSet(string, interface{}) error")
	fmt.Fprintf(&buf, "\nRemove(string) error")

	// These are used to deal with encoded headers
	fmt.Fprintf(&buf, "\nEncode() ([]byte, error)")
	fmt.Fprintf(&buf, "\nDecode([]byte) error")

	// Access private parameters
	fmt.Fprintf(&buf, "\n// PrivateParams returns the map containing the non-standard ('private') parameters")
	fmt.Fprintf(&buf, "\n// in the associated header. WARNING: DO NOT USE PrivateParams()")
	fmt.Fprintf(&buf, "\n// IF YOU HAVE CONCURRENT CODE ACCESSING THEM. Use AsMap() to")
	fmt.Fprintf(&buf, "\n// get a copy of the entire header instead")
	fmt.Fprintf(&buf, "\nPrivateParams() map[string]interface{}")

	fmt.Fprintf(&buf, "\nClone(context.Context) (Headers, error)")
	fmt.Fprintf(&buf, "\nCopy(context.Context, Headers) error")
	fmt.Fprintf(&buf, "\nMerge(context.Context, Headers) (Headers, error)")

	fmt.Fprintf(&buf, "\n}")

	fmt.Fprintf(&buf, "\n\ntype stdHeaders struct {")
	for _, f := range fields {
		fmt.Fprintf(&buf, "\n%s %s // %s", f.name, fieldStorageType(f.typ), f.comment)
	}
	fmt.Fprintf(&buf, "\nprivateParams map[string]interface{}")
	fmt.Fprintf(&buf, "\nmu *sync.RWMutex")
	fmt.Fprintf(&buf, "\n}") // end type StandardHeaders

	// Proxy is used when unmarshaling headers
	fmt.Fprintf(&buf, "\n\ntype standardHeadersMarshalProxy struct {")
	for _, f := range fields {
		switch f.name {
		case jwkKey, ephemeralPublicKey, agreementPartyUInfo, agreementPartyVInfo:
			fmt.Fprintf(&buf, "\nX%s json.RawMessage %s", f.name, f.jsonTag)
		default:
			if fieldStorageTypeIsIndirect(f.typ) {
				fmt.Fprintf(&buf, "\nX%s *%s %s", f.name, f.typ, f.jsonTag)
			} else {
				fmt.Fprintf(&buf, "\nX%s %s %s", f.name, f.typ, f.jsonTag)
			}
		}
	}
	fmt.Fprintf(&buf, "\n}") // end type StandardHeaders

	fmt.Fprintf(&buf, "\n\nfunc NewHeaders() Headers {")
	fmt.Fprintf(&buf, "\nreturn &stdHeaders{")
	fmt.Fprintf(&buf, "\nmu: &sync.RWMutex{},")
	fmt.Fprintf(&buf, "\nprivateParams: map[string]interface{}{},")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\n}")

	for _, f := range fields {
		fmt.Fprintf(&buf, "\n\nfunc (h *stdHeaders) %s() %s{", f.method, f.typ)
		fmt.Fprintf(&buf, "\nh.mu.RLock()")
		fmt.Fprintf(&buf, "\ndefer h.mu.RUnlock()")
		if !fieldStorageTypeIsIndirect(f.typ) {
			fmt.Fprintf(&buf, "\nreturn h.%s", f.name)
		} else {
			fmt.Fprintf(&buf, "\nif h.%s == nil {", f.name)
			fmt.Fprintf(&buf, "\nreturn %s", zeroval(f.typ))
			fmt.Fprintf(&buf, "\n}")
			fmt.Fprintf(&buf, "\nreturn *(h.%s)", f.name)
		}
		fmt.Fprintf(&buf, "\n}") // func (h *stdHeaders) %s() %s
	}

	// Generate a function that iterates through all of the keys
	// in this header.
	fmt.Fprintf(&buf, "\n\nfunc (h *stdHeaders) iterate(ctx context.Context, ch chan *HeaderPair) {")
	fmt.Fprintf(&buf, "\ndefer close(ch)")
	fmt.Fprintf(&buf, "\nh.mu.RLock()")
	fmt.Fprintf(&buf, "\ndefer h.mu.RUnlock()")
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
	fmt.Fprintf(&buf, "\nh.mu.RLock()")
	fmt.Fprintf(&buf, "\ndefer h.mu.RUnlock()")
	fmt.Fprintf(&buf, "\nreturn h.privateParams")
	fmt.Fprintf(&buf, "\n}")

	fmt.Fprintf(&buf, "\n\nfunc (h *stdHeaders) Get(name string) (interface{}, bool) {")
	fmt.Fprintf(&buf, "\nh.mu.RLock()")
	fmt.Fprintf(&buf, "\ndefer h.mu.RUnlock()")
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
	fmt.Fprintf(&buf, "\nh.mu.Lock()")
	fmt.Fprintf(&buf, "\ndefer h.mu.Unlock()")
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
			if f.name == "contentEncryption" {
				// check for non-empty string, because empty content encryption is just baaaaaad
				fmt.Fprintf(&buf, "\nif v == \"\" {")
				fmt.Fprintf(&buf, "\nreturn errors.New(`%#v field cannot be an empty string`)", f.key)
				fmt.Fprintf(&buf, "\n}")
			}

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

	fmt.Fprintf(&buf, "\n\nfunc (h *stdHeaders) Remove(key string) error {")
	fmt.Fprintf(&buf, "\nh.mu.Lock()")
	fmt.Fprintf(&buf, "\ndefer h.mu.Unlock()")
	fmt.Fprintf(&buf, "\nswitch key {")
	for _, f := range fields {
		fmt.Fprintf(&buf, "\ncase %sKey:", f.method)
		fmt.Fprintf(&buf, "\nh.%s = nil", f.name)
	}
	fmt.Fprintf(&buf, "\ndefault:")
	fmt.Fprintf(&buf, "\ndelete(h.privateParams, key)")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\nreturn nil") // currently unused, but who knows
	fmt.Fprintf(&buf, "\n}")

	fmt.Fprintf(&buf, "\n\nfunc (h *stdHeaders) UnmarshalJSON(buf []byte) error {")
	for _, f := range fields {
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

	for _, f := range fields {
		if f.typ == "string" {
			fmt.Fprintf(&buf, "\ncase %sKey:", f.method)
			fmt.Fprintf(&buf, "\nif err := json.AssignNextStringToken(&h.%s, dec); err != nil {", f.name)
			fmt.Fprintf(&buf, "\nreturn errors.Wrapf(err, `failed to decode value for key %%s`, %sKey)", f.method)
			fmt.Fprintf(&buf, "\n}")
		} else if f.typ == "[]byte" {
			name := f.method
			fmt.Fprintf(&buf, "\ncase %sKey:", name)
			fmt.Fprintf(&buf, "\nif err := json.AssignNextBytesToken(&h.%s, dec); err != nil {", f.name)
			fmt.Fprintf(&buf, "\nreturn errors.Wrapf(err, `failed to decode value for key %%s`, %sKey)", name)
			fmt.Fprintf(&buf, "\n}")
		} else if f.typ == "jwk.Key" {
			name := f.method
			fmt.Fprintf(&buf, "\ncase %sKey:", name)
			fmt.Fprintf(&buf, "\nvar buf json.RawMessage")
			fmt.Fprintf(&buf, "\nif err := dec.Decode(&buf); err != nil {")
			fmt.Fprintf(&buf, "\nreturn errors.Wrapf(err, `failed to decode value for key %%s`, %sKey)", name)
			fmt.Fprintf(&buf, "\n}")
			fmt.Fprintf(&buf, "\nkey, err := jwk.ParseKey(buf)")
			fmt.Fprintf(&buf, "\nif err != nil {")
			fmt.Fprintf(&buf, "\nreturn errors.Wrapf(err, `failed to parse JWK for key %%s`, %sKey)", name)
			fmt.Fprintf(&buf, "\n}")
			fmt.Fprintf(&buf, "\nh.%s = key", f.name)
		} else if strings.HasPrefix(f.typ, "[]") {
			name := f.method
			fmt.Fprintf(&buf, "\ncase %sKey:", name)
			fmt.Fprintf(&buf, "\nvar decoded %s", f.typ)
			fmt.Fprintf(&buf, "\nif err := dec.Decode(&decoded); err != nil {")
			fmt.Fprintf(&buf, "\nreturn errors.Wrapf(err, `failed to decode value for key %%s`, %sKey)", name)
			fmt.Fprintf(&buf, "\n}")
			fmt.Fprintf(&buf, "\nh.%s = decoded", f.name)
		} else {
			name := f.method
			fmt.Fprintf(&buf, "\ncase %sKey:", name)
			fmt.Fprintf(&buf, "\nvar decoded %s", f.typ)
			fmt.Fprintf(&buf, "\nif err := dec.Decode(&decoded); err != nil {")
			fmt.Fprintf(&buf, "\nreturn errors.Wrapf(err, `failed to decode value for key %%s`, %sKey)", name)
			fmt.Fprintf(&buf, "\n}")
			fmt.Fprintf(&buf, "\nh.%s = &decoded", f.name)
		}
	}
	fmt.Fprintf(&buf, "\ndefault:")
	fmt.Fprintf(&buf, "\nvar decoded interface{}")
	fmt.Fprintf(&buf, "\nif err := dec.Decode(&decoded); err != nil {")
	fmt.Fprintf(&buf, "\nreturn errors.Wrapf(err, `failed to decode field %%s`, tok)")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\nif h.privateParams == nil {")
	fmt.Fprintf(&buf, "\nh.privateParams = make(map[string]interface{})")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\nh.privateParams[tok] = decoded")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\ndefault:")
	fmt.Fprintf(&buf, "\nreturn errors.Errorf(`invalid token %%T`, tok)")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\n}")

	fmt.Fprintf(&buf, "\nreturn nil")
	fmt.Fprintf(&buf, "\n}")

	fmt.Fprintf(&buf, "\n\nfunc (h stdHeaders) MarshalJSON() ([]byte, error) {")
	fmt.Fprintf(&buf, "\nctx, cancel := context.WithCancel(context.Background())")
	fmt.Fprintf(&buf, "\ndefer cancel()")
	fmt.Fprintf(&buf, "\ndata := make(map[string]interface{})")
	fmt.Fprintf(&buf, "\nfields := make([]string, 0, %d)", len(fields))
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
	fmt.Fprintf(&buf, "\nerrors.Errorf(`failed to encode value for field %%s`, f)")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\nbuf.Truncate(buf.Len()-1)")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\nbuf.WriteByte('}')")
	fmt.Fprintf(&buf, "\nret := make([]byte, buf.Len())")
	fmt.Fprintf(&buf, "\ncopy(ret, buf.Bytes())")
	fmt.Fprintf(&buf, "\nreturn ret, nil")
	fmt.Fprintf(&buf, "\n}")

	if err := codegen.WriteFile(`headers_gen.go`, &buf, codegen.WithFormatCode(true)); err != nil {
		if cfe, ok := err.(codegen.CodeFormatError); ok {
			fmt.Fprint(os.Stderr, cfe.Source())
		}
		return errors.Wrap(err, `failed to write to headers_gen.go`)
	}
	return nil
}
