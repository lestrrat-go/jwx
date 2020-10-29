package jwx_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx"
	"github.com/lestrrat-go/jwx/internal/json"
	"github.com/stretchr/testify/assert"
)

type jsonUnmarshalWrapper struct {
	buf []byte
}

func (w jsonUnmarshalWrapper) Decode(v interface{}) error {
	return json.Unmarshal(w.buf, v)
}

func TestDecoderSetting(t *testing.T) {
	const src = `{"foo": 1}`

	for _, useNumber := range []bool{true, false} {
		useNumber := useNumber
		t.Run(fmt.Sprintf("jwx.WithUseNumber(%t)", useNumber), func(t *testing.T) {
			if useNumber {
				jwx.DecoderSettings(jwx.WithUseNumber(useNumber))
				t.Cleanup(func() {
					jwx.DecoderSettings(jwx.WithUseNumber(false))
				})
			}

			// json.NewDecoder must be called AFTER the above jwx.DecoderSettings call
			decoders := []struct {
				Name    string
				Decoder interface{ Decode(interface{}) error }
			}{
				{Name: "Decoder", Decoder: json.NewDecoder(strings.NewReader(src))},
				{Name: "Unmarshal", Decoder: jsonUnmarshalWrapper{buf: []byte(src)}},
			}

			for _, tc := range decoders {
				tc := tc
				t.Run(tc.Name, func(t *testing.T) {
					var m map[string]interface{}
					if !assert.NoError(t, tc.Decoder.Decode(&m), `Decode should succeed`) {
						return
					}

					v, ok := m["foo"]
					if !assert.True(t, ok, `m["foo"] should exist`) {
						return
					}

					if useNumber {
						if !assert.Equal(t, json.Number("1"), v, `v should be a json.Number object`) {
							return
						}
					} else {
						if !assert.Equal(t, float64(1), v, `v should be a float64`) {
							return
						}
					}
				})
			}
		})
	}
}
