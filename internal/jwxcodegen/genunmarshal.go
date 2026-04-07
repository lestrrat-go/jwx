package jwxcodegen

import (
	"strings"

	"github.com/lestrrat-go/codegen"
)

// GenerateUnmarshalCases emits case clauses for the streaming JSON decoder
// switch inside UnmarshalJSON. Each field type uses a different decode strategy:
//   - string: json.AssignNextStringToken
//   - []byte: json.AssignNextBytesToken
//   - jwk.Key: dec.ReadValue() then jwk.ParseKey
//   - slice types ([]...): json.UnmarshalDecode into slice, assign directly
//   - noDeref pointer types or IsPointer types: json.UnmarshalDecode into PointerElem, assign &decoded
//   - other types: json.UnmarshalDecode into type, assign &decoded
//
// The decodeCtxExpr parameter is the expression for the decode context passed to
// AssignNextStringToken (e.g., "nil" for genheaders, "t.dc" for genjwt, "h.dc" for genjwk).
//
// Fields in the Skip set are not emitted; the caller handles them separately.
func GenerateUnmarshalCases(o *codegen.Output, cfg CaseConfig, decodeCtxExpr string) {
	recv := cfg.receiverName()
	for _, f := range cfg.Fields {
		if _, ok := cfg.Skip[f.Name(false)]; ok {
			continue
		}
		keyName := cfg.KeyName(f)
		if f.Type() == "string" {
			o.L("case %s:", keyName)
			o.L("if err := json.AssignNextStringToken(&%s.%s, dec, %s); err != nil {", recv, f.Name(false), decodeCtxExpr)
			o.L("return fmt.Errorf(`failed to decode value for key %%s: %%w`, %s, err)", keyName)
			o.L("}")
		} else if f.Type() == "[]byte" {
			o.L("case %s:", keyName)
			o.L("if err := json.AssignNextBytesToken(&%s.%s, dec); err != nil {", recv, f.Name(false))
			o.L("return fmt.Errorf(`failed to decode value for key %%s: %%w`, %s, err)", keyName)
			o.L("}")
		} else if f.Type() == "jwk.Key" {
			o.L("case %s:", keyName)
			o.L("raw, err := dec.ReadValue()")
			o.L("if err != nil {")
			o.L("return fmt.Errorf(`failed to decode value for key %%s: %%w`, %s, err)", keyName)
			o.L("}")
			o.L("key, err := jwk.ParseKey[jwk.Key](raw)")
			o.L("if err != nil {")
			o.L("return fmt.Errorf(`failed to parse JWK for key %%s: %%w`, %s, err)", keyName)
			o.L("}")
			o.L("%s.%s = key", recv, f.Name(false))
		} else if strings.HasPrefix(f.Type(), "[]") || f.Bool(`direct_storage`) {
			o.L("case %s:", keyName)
			o.L("var decoded %s", f.Type())
			o.L("if err := json.UnmarshalDecode(dec, &decoded); err != nil {")
			o.L("return fmt.Errorf(`failed to decode value for key %%s: %%w`, %s, err)", keyName)
			o.L("}")
			o.L("%s.%s = decoded", recv, f.Name(false))
		} else if f.Bool(`noDeref`) || IsPointer(f) {
			o.L("case %s:", keyName)
			o.L("var decoded %s", PointerElem(f))
			o.L("if err := json.UnmarshalDecode(dec, &decoded); err != nil {")
			o.L("return fmt.Errorf(`failed to decode value for key %%s: %%w`, %s, err)", keyName)
			o.L("}")
			o.L("%s.%s = &decoded", recv, f.Name(false))
		} else {
			o.L("case %s:", keyName)
			o.L("var decoded %s", f.Type())
			o.L("if err := json.UnmarshalDecode(dec, &decoded); err != nil {")
			o.L("return fmt.Errorf(`failed to decode value for key %%s: %%w`, %s, err)", keyName)
			o.L("}")
			o.L("%s.%s = &decoded", recv, f.Name(false))
		}
	}
}
