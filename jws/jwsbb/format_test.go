package jwsbb_test

import (
	stdbase64 "encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jws/jwsbb"
	"github.com/stretchr/testify/require"
)

func TestSignBufferCapacity(t *testing.T) {
	t.Parallel()

	encoders := []struct {
		name    string
		encoder *stdbase64.Encoding
	}{
		{"raw", stdbase64.RawURLEncoding},
		{"padded", stdbase64.URLEncoding},
	}

	// Header and payload lengths 0-4 cover every base64 remainder for each
	// component, so the sizing is checked against all rounding combinations.
	for _, enc := range encoders {
		for _, encodePayload := range []bool{true, false} {
			for hdrLen := range 5 {
				for payloadLen := range 5 {
					name := fmt.Sprintf("%s/encodePayload=%t/hdr=%d/payload=%d", enc.name, encodePayload, hdrLen, payloadLen)
					t.Run(name, func(t *testing.T) {
						t.Parallel()
						hdr := []byte(strings.Repeat("h", hdrLen))
						payload := []byte(strings.Repeat("p", payloadLen))

						want := enc.encoder.EncodeToString(hdr) + "."
						if encodePayload {
							want += enc.encoder.EncodeToString(payload)
						} else {
							want += string(payload)
						}

						got := jwsbb.SignBuffer(nil, hdr, payload, enc.encoder, encodePayload)
						require.Equal(t, want, string(got), "signing input should match an independent encoding")
						require.Equal(t, len(want), cap(got), "nil buffer should be allocated at exactly the output size")

						buf := make([]byte, 0, len(want))
						got = jwsbb.SignBuffer(buf, hdr, payload, enc.encoder, encodePayload)
						require.Equal(t, want, string(got), "signing input should match an independent encoding")
						require.Same(t, &buf[:1][0], &got[0], "caller buffer with exactly enough capacity should be reused")
					})
				}
			}
		}
	}
}
