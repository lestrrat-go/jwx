package padbuf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPadBuffer(t *testing.T) {
	for i := 0; i < 256; i++ {
		buf := make([]byte, i)
		pb := PadBuffer(buf)

		pb = pb.Pad(16)

		if !assert.Equal(t, pb.Len()%16, 0, "pb should be multiple of 16") {
			return
		}

		pb, err := pb.Unpad(16)
		if !assert.NoError(t, err, "Unpad return successfully") {
			return
		}

		if !assert.Len(t, pb, i, "Unpad should result in len = %d", i) {
			return
		}
	}
}
