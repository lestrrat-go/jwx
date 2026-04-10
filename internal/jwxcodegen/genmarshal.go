package jwxcodegen

import "github.com/lestrrat-go/codegen"

// GenerateMarshalJSON emits a complete MarshalJSON method. The pattern builds a
// pooled []fieldPair slice under RLock, sorts, then writes JSON directly to a
// pooled buffer using fmt.Fprintf and json.Marshal. []byte values are base64-encoded.
//
// The caller must ensure the target package contains the fieldPair type,
// fieldPairPool, getFieldPairList, putFieldPairList, and fieldPairLess.
//
// Used by genheaders and genjwk, but NOT genjwt (which uses claimPair pool).
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
	o.L("buf.WriteByte('{')")
	o.L("for i, p := range pairs {")
	o.L("if i > 0 { buf.WriteByte(',') }")
	o.L("buf.WriteByte('\"')")
	o.L("buf.WriteString(p.Name)")
	o.L("buf.WriteString(`\":`)")
	o.L("switch v := p.Value.(type) {")
	o.L("case []byte:")
	o.L("buf.WriteByte('\"')")
	o.L("buf.WriteString(base64.EncodeToString(v))")
	o.L("buf.WriteByte('\"')")
	o.L("default:")
	o.L("valBytes, err := json.Marshal(v)")
	o.L("if err != nil {")
	o.L("return nil, fmt.Errorf(`failed to encode value for field %%s: %%w`, p.Name, err)")
	o.L("}")
	o.L("buf.Write(valBytes)")
	o.L("}")
	o.L("}")
	o.L("buf.WriteByte('}')")
	o.L("putFieldPairList(pairs)")
	o.L("ret := make([]byte, buf.Len())")
	o.L("copy(ret, buf.Bytes())")
	o.L("return ret, nil")
	o.L("}")
}
