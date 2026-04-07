package jwxcodegen

import "github.com/lestrrat-go/codegen"

// GenerateFieldCases emits case clauses for a Field(name string) (any, bool) switch.
// Each case does a nil check, then returns the value (dereferenced for indirect types).
//
// The fieldStorageTypeIsIndirect parameter controls whether a field's type is stored
// behind a pointer. Each generator has slightly different rules for this.
func GenerateFieldCases(o *codegen.Output, cfg CaseConfig, fieldStorageTypeIsIndirect func(codegen.Field) bool) {
	recv := cfg.receiverName()
	for _, f := range cfg.Fields {
		if _, ok := cfg.Skip[f.Name(false)]; ok {
			continue
		}
		o.L("case %s:", cfg.KeyName(f))
		o.L("if %s.%s == nil {", recv, f.Name(false))
		o.L("return nil, false")
		o.L("}")
		if f.Bool(`hasGet`) {
			o.L("return %s.%s.Get(), true", recv, f.Name(false))
		} else if fieldStorageTypeIsIndirect(f) {
			o.L("return *(%s.%s), true", recv, f.Name(false))
		} else {
			o.L("return %s.%s, true", recv, f.Name(false))
		}
	}
}
