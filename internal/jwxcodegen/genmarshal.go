package jwxcodegen

import "github.com/lestrrat-go/codegen"

// GenerateMarshalJSON emits a complete MarshalJSON method. The pattern builds a
// map[string]any + []string keys under RLock, sorts, then uses json/v2 encoder
// with WriteToken/MarshalEncode. []byte values are base64-encoded.
//
// Used by genheaders and genjwk, but NOT genjwt (which uses pair-pool).
func GenerateMarshalJSON(o *codegen.Output, cfg MarshalConfig) {
	recv := cfg.ReceiverName
	structName := cfg.StructName
	fields := cfg.Fields
	privateParams := cfg.PrivateParamsField
	fieldStorageTypeIsIndirect := cfg.FieldStorageTypeIsIndirect

	o.LL("func (%s *%s) MarshalJSON() ([]byte, error) {", recv, structName)

	// For genjwk, RLock comes after initial data setup; for genheaders it's also after.
	// Both patterns: build data map, populate under RLock, then sort and encode.
	o.L("%s.mu.RLock()", recv)

	o.L("data := make(map[string]any)")
	capExpr := len(fields)
	o.L("keys := make([]string, 0, %d+len(%s.%s))", capExpr, recv, privateParams)

	// Always-present entries (e.g., KeyTypeKey for genjwk)
	for _, entry := range cfg.AlwaysPresentEntries {
		o.L("data[%s] = %s", entry.KeyName, entry.Value)
		o.L("keys = append(keys, %s)", entry.KeyName)
	}

	for _, f := range fields {
		keyName := cfg.KeyName(f)
		o.L("if %s.%s != nil {", recv, f.Name(false))
		if fieldStorageTypeIsIndirect(f) {
			o.L("data[%s] = *(%s.%s)", keyName, recv, f.Name(false))
		} else {
			o.L("data[%s] = %s.%s", keyName, recv, f.Name(false))
		}
		o.L("keys = append(keys, %s)", keyName)
		o.L("}")
	}
	o.L("for k, v := range %s.%s {", recv, privateParams)
	o.L("data[k] = v")
	o.L("keys = append(keys, k)")
	o.L("}")
	o.L("%s.mu.RUnlock()", recv)

	o.L("slices.Sort(keys)")
	o.LL("buf := pool.BytesBuffer().Get()")
	o.L("defer pool.BytesBuffer().Put(buf)")
	o.L("enc := json.NewEncoder(buf)")
	o.L("enc.WriteToken(jsontext.BeginObject)")
	o.L("for _, k := range keys {")
	o.L("enc.WriteToken(jsontext.String(k))")
	o.L("switch v := data[k].(type) {")
	o.L("case []byte:")
	o.L("enc.WriteToken(jsontext.String(base64.EncodeToString(v)))")
	o.L("default:")
	o.L("if err := json.MarshalEncode(enc, v); err != nil {")
	o.L("return nil, fmt.Errorf(`failed to encode value for field %%s: %%w`, k, err)")
	o.L("}")
	o.L("}")
	o.L("}")
	o.L("enc.WriteToken(jsontext.EndObject)")
	o.L("ret := make([]byte, buf.Len())")
	o.L("copy(ret, buf.Bytes())")
	o.L("return ret, nil")
	o.L("}")
}
