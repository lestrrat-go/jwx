package jwxcodegen

import (
	"strings"

	"github.com/lestrrat-go/codegen"
)

// IsPointer returns true if the field's type starts with "*".
func IsPointer(f codegen.Field) bool {
	return strings.HasPrefix(f.Type(), `*`)
}

// PointerElem returns the field's type with the leading "*" stripped.
// If the type does not start with "*", it is returned as-is.
func PointerElem(f codegen.Field) string {
	return strings.TrimPrefix(f.Type(), `*`)
}

// FieldStorageType returns the type used for struct field storage.
// If the type requires indirect storage, a "*" prefix is added.
func FieldStorageType(f codegen.Field) string {
	if FieldStorageTypeIsIndirect(f) {
		return `*` + f.Type()
	}
	return f.Type()
}

// FieldStorageTypeIsIndirect returns true if a field's type should be
// stored as a pointer in the struct (indirect storage). Types that are
// already pointer-like (starting with "*" or "[]") or that have the
// direct_storage YAML attribute set to true are stored directly.
func FieldStorageTypeIsIndirect(f codegen.Field) bool {
	if f.Bool("direct_storage") {
		return false
	}
	s := f.Type()
	return !(strings.HasPrefix(s, `*`) || strings.HasPrefix(s, `[]`))
}

// FieldStorageTypeIsIndirectByName returns true if a type name string
// should be stored as a pointer. This is the legacy version that checks
// by type name string rather than field attributes.
func FieldStorageTypeIsIndirectByName(s string) bool {
	return !(s == "jwk.Key" || strings.HasPrefix(s, `*`) || strings.HasPrefix(s, `[]`))
}
