package jws

import (
	"context"

	"github.com/pkg/errors"
)

// Iterate returns a channel that successively returns all the
// header name and values.
func (h *stdHeaders) Iterate(ctx context.Context) <-chan *HeaderPair {
	ch := make(chan *HeaderPair)
	go h.iterate(ctx, ch)
	return ch
}

func (h *stdHeaders) Walk(ctx context.Context, visitor Visitor) error {
	// XXX did we need to check for error cases here when reading from a channel?
	for pair := range h.Iterate(ctx) {
		if err := visitor.Visit(pair.Name, pair.Value); err != nil {
			return errors.Wrapf(err, `failed to visit key %s`, pair.Name)
		}
	}
	return nil
}

func (h *stdHeaders) AsMap(ctx context.Context) map[string]interface{} {
	m := make(map[string]interface{})

	for pair := range h.Iterate(ctx) {
		m[pair.Name] = pair.Value
	}

	return m
}
