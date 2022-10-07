package jws

import (
	"fmt"
)

func (v *stdHeaders) rawBuffer() []byte {
	return v.raw
}

func (v *stdHeaders) UnmarshalJSON(data []byte) error {
	if err := v.unmarshalJSON(data); err != nil {
		return err
	}
	v.raw = data
	return nil
}

// Copy copies the values tored in the header to `dst`. Existing
// values stored in `dst` are preserved, except when fields with the same
// name are present. In such cases the old value stored in `dst` is
// overwritten.
func (v *stdHeaders) Copy(dst Headers) error {
	for _, key := range v.FieldNames() {
		var val interface{}
		if err := v.Get(key, &val); err != nil {
			return fmt.Errorf(`failed to get header %q during copy: %w`, key, err)
		}

		if err := dst.Set(key, val); err != nil {
			return fmt.Errorf(`failed to set header %q during copy: %w`, key, err)
		}
	}
	return nil
}

// mergeHeaders merges two headers, and works even if the first Header
// object is nil. This is not exported because ATM it felt like this
// function is not frequently used, and MergeHeaders seemed a clunky name
func mergeHeaders(h1, h2 Headers) (Headers, error) {
	h3 := NewHeaders()

	if h1 != nil {
		if err := h1.Copy(h3); err != nil {
			return nil, fmt.Errorf(`failed to copy headers from first Header during merge: %w`, err)
		}
	}

	if h2 != nil {
		if err := h2.Copy(h3); err != nil {
			return nil, fmt.Errorf(`failed to copy headers from second Header during merge: %w`, err)
		}
	}

	return h3, nil
}

func (v *stdHeaders) Merge(h2 Headers) (Headers, error) {
	return mergeHeaders(v, h2)
}
