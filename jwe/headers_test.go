package jwe_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe"
	"github.com/stretchr/testify/assert"
)

func TestHeaders_Encode(t *testing.T) {
	h1 := jwe.NewHeaders()
	h1.Set(jwe.AlgorithmKey, jwa.A128GCMKW)
	h1.Set("foo", "bar")

	buf, err := h1.Encode()
	if !assert.NoError(t, err, `h1.Encode should succeed`) {
		return
	}

	h2 := jwe.NewHeaders()
	if !assert.NoError(t, h2.Decode(buf), `h2.Decode should succeed`) {
		return
	}

	if !assert.Equal(t, h1, h2, `objects should match`) {
		return
	}
}
