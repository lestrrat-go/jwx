package jwxcodegen

import (
	"strings"

	"github.com/lestrrat-go/codegen"
)

// GenerateSetCases emits case clauses for a setNoLock(name string, value any) error switch.
//
// The fieldStorageTypeIsIndirect parameter controls whether a field's type is stored
// behind a pointer. Each generator has slightly different rules for this.
//
// Fields in the Skip set are not emitted; the caller handles them (e.g., algorithm
// has custom handling in genheaders and genjwk).
func GenerateSetCases(o *codegen.Output, cfg CaseConfig, fieldStorageTypeIsIndirect func(codegen.Field) bool) {
	recv := cfg.receiverName()
	for _, f := range cfg.Fields {
		if _, ok := cfg.Skip[f.Name(false)]; ok {
			continue
		}
		o.L("case %s:", cfg.KeyName(f))
		if f.Bool(`hasAccept`) {
			o.L("var acceptor %s", PointerElem(f))
			o.L("if err := acceptor.Accept(value); err != nil {")
			o.L("return fmt.Errorf(`invalid value for %%s key: %%w`, %s, err)", cfg.KeyName(f))
			o.L("}")
			if fieldStorageTypeIsIndirect(f) || IsPointer(f) {
				o.L("%s.%s = &acceptor", recv, f.Name(false))
			} else {
				o.L("%s.%s = acceptor", recv, f.Name(false))
			}
			o.L("return nil")
		} else {
			o.L("if v, ok := value.(%s); ok {", f.Type())
			if f.Bool(`reject_empty`) {
				o.L("if v == %s {", codegen.ZeroVal(f.Type()))
				o.L("return fmt.Errorf(`%#v field cannot be an empty string`)", f.JSON())
				o.L("}")
			}
			if fieldStorageTypeIsIndirect(f) {
				o.L("%s.%s = &v", recv, f.Name(false))
			} else if strings.HasPrefix(f.Type(), "[]") {
				o.L("if v == nil {")
				o.L("%s.%s = nil", recv, f.Name(false))
				o.L("} else {")
				o.L("%s.%s = make(%s, len(v))", recv, f.Name(false), f.Type())
				o.L("copy(%s.%s, v)", recv, f.Name(false))
				o.L("}")
			} else {
				o.L("%s.%s = v", recv, f.Name(false))
			}
			o.L("return nil")
			o.L("}")
			o.L("return fmt.Errorf(`invalid value for %%s key: %%T`, %s, value)", cfg.KeyName(f))
		}
	}
}
