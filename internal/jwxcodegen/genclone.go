package jwxcodegen

import (
	"strings"

	"github.com/lestrrat-go/codegen"
)

// GenerateCloneFrom emits a complete cloneFrom(src *StructName) method.
// Per-field nil-check with type-appropriate copy:
//   - Slices ([] prefix or List suffix): slices.Clone
//   - noDeref pointers: direct copy
//   - Other pointers: shallow copy
//   - Indirect types: tmp := *(src.field); dst.field = &tmp
//   - Direct types: direct copy
//
// Also copies the private params map and any extra fields.
func GenerateCloneFrom(o *codegen.Output, cfg CloneConfig) {
	structName := cfg.StructName
	fields := cfg.Fields
	privateParams := cfg.PrivateParamsField
	fieldStorageTypeIsIndirect := cfg.FieldStorageTypeIsIndirect

	o.LL("func (dst *%s) cloneFrom(src *%s) {", structName, structName)
	o.L("src.mu.RLock()")
	o.L("defer src.mu.RUnlock()")
	o.L("dst.mu.Lock()")
	o.L("defer dst.mu.Unlock()")

	// Extra fields that are direct-copied before field iteration (e.g., options)
	for _, ef := range cfg.ExtraFieldsToCopy {
		if ef.DirectCopy {
			o.L("dst.%s = src.%s", ef.Name, ef.Name)
		}
	}

	for _, f := range fields {
		fname := f.Name(false)
		o.L("if src.%s != nil {", fname)
		if strings.HasPrefix(f.Type(), "[]") || strings.HasSuffix(f.Type(), "List") {
			o.L("dst.%s = slices.Clone(src.%s)", fname, fname)
		} else if IsPointer(f) && f.Bool(`noDeref`) {
			o.L("dst.%s = src.%s", fname, fname)
		} else if IsPointer(f) {
			// Pointer type without noDeref — shallow copy
			o.L("dst.%s = src.%s", fname, fname)
		} else if fieldStorageTypeIsIndirect(f) {
			o.L("tmp := *(src.%s)", fname)
			o.L("dst.%s = &tmp", fname)
		} else {
			o.L("dst.%s = src.%s", fname, fname)
		}
		o.L("} else {")
		o.L("dst.%s = nil", fname)
		o.L("}")
	}

	// Private params
	o.L("if len(src.%s) > 0 {", privateParams)
	o.L("dst.%s = make(map[string]any, len(src.%s))", privateParams, privateParams)
	o.L("for k, v := range src.%s {", privateParams)
	o.L("dst.%s[k] = v", privateParams)
	o.L("}")
	o.L("} else {")
	if cfg.InitPrivateParams {
		o.L("dst.%s = make(map[string]any)", privateParams)
	} else {
		o.L("dst.%s = nil", privateParams)
	}
	o.L("}")

	// Extra fields that are not direct-copied (e.g., "raw" with slices.Clone)
	for _, ef := range cfg.ExtraFieldsToCopy {
		if ef.DirectCopy {
			continue
		}
		if ef.IsSlice {
			o.L("dst.%s = slices.Clone(src.%s)", ef.Name, ef.Name)
		} else {
			o.L("dst.%s = src.%s", ef.Name, ef.Name)
		}
	}

	o.L("}")
}
