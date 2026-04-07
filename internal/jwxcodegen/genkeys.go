package jwxcodegen

import "github.com/lestrrat-go/codegen"

// GenerateKeysMethod emits a complete Keys() []string method.
// It iterates fields with nil-check, appends to a keys slice,
// then appends private params.
func GenerateKeysMethod(o *codegen.Output, cfg KeysConfig) {
	recv := cfg.ReceiverName
	structName := cfg.StructName
	fields := cfg.Fields
	privateParams := cfg.PrivateParamsField

	o.LL("func (%s *%s) Keys() []string {", recv, structName)
	o.L("%s.mu.RLock()", recv)
	o.L("defer %s.mu.RUnlock()", recv)
	o.L("keys := make([]string, 0, %d+len(%s.%s))", len(fields), recv, privateParams)

	// Always-present keys (e.g., KeyTypeKey for genjwk)
	for _, k := range cfg.AlwaysPresentKeys {
		o.L("keys = append(keys, %s)", k)
	}

	for _, f := range fields {
		keyName := cfg.KeyName(f)
		o.L("if %s.%s != nil {", recv, f.Name(false))
		o.L("keys = append(keys, %s)", keyName)
		o.L("}")
	}
	o.L("for k := range %s.%s {", recv, privateParams)
	o.L("keys = append(keys, k)")
	o.L("}")
	o.L("return keys")
	o.L("}")
}
