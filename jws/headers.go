package jws

import (
	"fmt"
)

func (h *stdHeaders) Copy(dst Headers) error {
	for _, k := range h.Keys() {
		v, ok := h.Field(k)
		if !ok {
			return fmt.Errorf(`failed to get header %q`, k)
		}
		if err := dst.Set(k, v); err != nil {
			return fmt.Errorf(`failed to set header %q: %w`, k, err)
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
			return nil, fmt.Errorf(`failed to copy headers from first Header: %w`, err)
		}
	}

	if h2 != nil {
		if err := h2.Copy(h3); err != nil {
			return nil, fmt.Errorf(`failed to copy headers from second Header: %w`, err)
		}
	}

	return h3, nil
}

func (h *stdHeaders) Merge(h2 Headers) (Headers, error) {
	return mergeHeaders(h, h2)
}

// Clone creates a deep copy of the header
func (h *stdHeaders) Clone() (Headers, error) {
	dst, _ := NewHeaders().(*stdHeaders)
	dst.cloneFrom(h)
	return dst, nil
}
