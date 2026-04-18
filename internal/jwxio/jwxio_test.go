package jwxio_test

import (
	"io"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v3/internal/jwxio"
	"github.com/stretchr/testify/require"
)

type endlessReader struct{ b byte }

func (r *endlessReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.b
	}
	return len(p), nil
}

type readTrackingReader struct {
	b     byte
	reads int
}

func (r *readTrackingReader) Read(p []byte) (int, error) {
	r.reads++
	for i := range p {
		p[i] = r.b
	}
	return len(p), nil
}

func TestReadAllFromFiniteSource(t *testing.T) {
	t.Parallel()

	t.Run("limited reader from finite source", func(t *testing.T) {
		t.Parallel()

		data, err := jwxio.ReadAllFromFiniteSource(io.LimitReader(strings.NewReader("hello"), 3), 4)
		require.NoError(t, err)
		require.Equal(t, []byte("hel"), data)
	})

	t.Run("limited reader bounds endless source", func(t *testing.T) {
		t.Parallel()

		data, err := jwxio.ReadAllFromFiniteSource(io.LimitReader(&endlessReader{b: 'x'}, 4), 4)
		require.NoError(t, err)
		require.Equal(t, []byte("xxxx"), data)
	})

	t.Run("endless source is rejected", func(t *testing.T) {
		t.Parallel()

		tracker := &readTrackingReader{b: 'x'}
		_, err := jwxio.ReadAllFromFiniteSource(tracker, 4)
		require.ErrorIs(t, err, jwxio.NonFiniteSourceError())
		require.Zero(t, tracker.reads)
	})

	t.Run("oversized limited reader is rejected before reading", func(t *testing.T) {
		t.Parallel()

		tracker := &readTrackingReader{b: 'x'}
		_, err := jwxio.ReadAllFromFiniteSource(&io.LimitedReader{R: tracker, N: 6}, 4)
		require.ErrorIs(t, err, jwxio.InputTooLargeError())
		require.Zero(t, tracker.reads)
	})
}
