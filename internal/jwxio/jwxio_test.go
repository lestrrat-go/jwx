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

func TestReadAllFromFiniteSource(t *testing.T) {
	t.Parallel()

	t.Run("limited reader from finite source", func(t *testing.T) {
		t.Parallel()

		data, err := jwxio.ReadAllFromFiniteSource(io.LimitReader(strings.NewReader("hello"), 3))
		require.NoError(t, err)
		require.Equal(t, []byte("hel"), data)
	})

	t.Run("limited reader bounds endless source", func(t *testing.T) {
		t.Parallel()

		data, err := jwxio.ReadAllFromFiniteSource(io.LimitReader(&endlessReader{b: 'x'}, 4))
		require.NoError(t, err)
		require.Equal(t, []byte("xxxx"), data)
	})

	t.Run("endless source is rejected", func(t *testing.T) {
		t.Parallel()

		_, err := jwxio.ReadAllFromFiniteSource(&endlessReader{b: 'x'})
		require.ErrorIs(t, err, jwxio.NonFiniteSourceError())
	})
}
