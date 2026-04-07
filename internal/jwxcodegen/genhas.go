package jwxcodegen

import "github.com/lestrrat-go/codegen"

// GenerateHasCases emits case clauses for a Has(name string) bool switch.
// Each case returns true if the field is non-nil.
func GenerateHasCases(o *codegen.Output, cfg CaseConfig) {
	recv := cfg.receiverName()
	for _, f := range cfg.Fields {
		if _, ok := cfg.Skip[f.Name(false)]; ok {
			continue
		}
		o.L("case %s:", cfg.KeyName(f))
		o.L("return %s.%s != nil", recv, f.Name(false))
	}
}
