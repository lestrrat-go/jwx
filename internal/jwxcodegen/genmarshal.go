package jwxcodegen

import "github.com/lestrrat-go/codegen"

// GenerateMarshalJSON emits a complete MarshalJSON method. The pattern builds a
// pooled []fieldPair slice under RLock, sorts, then uses json/v2 encoder
// with WriteToken/MarshalEncode. []byte values are base64-encoded.
//
// The caller must ensure the target package contains the fieldPair type,
// fieldPairPool, getFieldPairList, putFieldPairList, and fieldPairLess.
//
// Used by genheaders and genjwk, but NOT genjwt (which uses pair-pool).
func GenerateMarshalJSON(o *codegen.Output, cfg MarshalConfig) {
	recv := cfg.ReceiverName
	structName := cfg.StructName
	fields := cfg.Fields
	privateParams := cfg.PrivateParamsField
	fieldStorageTypeIsIndirect := cfg.FieldStorageTypeIsIndirect

	o.LL("func (%s *%s) MarshalJSON() ([]byte, error) {", recv, structName)

	o.L("pairs := getFieldPairList()")

	// Always-present entries (e.g., KeyTypeKey for genjwk)
	for _, entry := range cfg.AlwaysPresentEntries {
		o.L("pairs = append(pairs, fieldPair{Name: %s, Value: %s})", entry.KeyName, entry.Value)
	}

	o.L("%s.mu.RLock()", recv)

	for _, f := range fields {
		keyName := cfg.KeyName(f)
		o.L("if %s.%s != nil {", recv, f.Name(false))
		if fieldStorageTypeIsIndirect(f) {
			o.L("pairs = append(pairs, fieldPair{Name: %s, Value: *(%s.%s)})", keyName, recv, f.Name(false))
		} else {
			o.L("pairs = append(pairs, fieldPair{Name: %s, Value: %s.%s})", keyName, recv, f.Name(false))
		}
		o.L("}")
	}
	o.L("for k, v := range %s.%s {", recv, privateParams)
	o.L("pairs = append(pairs, fieldPair{Name: k, Value: v})")
	o.L("}")
	o.L("%s.mu.RUnlock()", recv)

	o.L("slices.SortFunc(pairs, fieldPairLess)")
	o.LL("buf := pool.BytesBuffer().Get()")
	o.L("defer pool.BytesBuffer().Put(buf)")
	o.L("enc := json.NewEncoder(buf)")
	o.L("enc.WriteToken(jsontext.BeginObject)")
	o.L("for _, p := range pairs {")
	o.L("enc.WriteToken(jsontext.String(p.Name))")
	o.L("switch v := p.Value.(type) {")
	o.L("case []byte:")
	o.L("enc.WriteToken(jsontext.String(base64.EncodeToString(v)))")
	o.L("default:")
	o.L("if err := json.MarshalEncode(enc, v); err != nil {")
	o.L("return nil, fmt.Errorf(`failed to encode value for field %%s: %%w`, p.Name, err)")
	o.L("}")
	o.L("}")
	o.L("}")
	o.L("enc.WriteToken(jsontext.EndObject)")
	o.L("putFieldPairList(pairs)")
	o.L("ret := make([]byte, buf.Len())")
	o.L("copy(ret, buf.Bytes())")
	o.L("return ret, nil")
	o.L("}")
}
