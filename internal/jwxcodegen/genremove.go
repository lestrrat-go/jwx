package jwxcodegen

import "github.com/lestrrat-go/codegen"

// GenerateRemoveCases emits case clauses for a Remove(key string) error switch.
// Each case sets the field to nil.
func GenerateRemoveCases(o *codegen.Output, cfg CaseConfig) {
	recv := cfg.receiverName()
	for _, f := range cfg.Fields {
		if _, ok := cfg.Skip[f.Name(false)]; ok {
			continue
		}
		o.L("case %s:", cfg.KeyName(f))
		o.L("%s.%s = nil", recv, f.Name(false))
	}
}
