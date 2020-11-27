package base64

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncodeToStringStd(t *testing.T) {
	t.Parallel()
	t.Run("Encodes to StdEncoding with padding", func(t *testing.T) {
		t.Parallel()
		out, err := base64.StdEncoding.DecodeString(EncodeToStringStd([]byte("Hello, World!")))
		assert.NoError(t, err)
		assert.NotNil(t, out)
	})
}
