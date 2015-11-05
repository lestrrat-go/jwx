package buffer

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuffer_Convert(t *testing.T) {
	v1 := []byte{'a', 'b', 'c'}
	b := Buffer(v1)

	if !assert.Equal(t, v1, b.Bytes()) {
		return
	}

	v2 := "abc"
	b = Buffer(v2)
	if !assert.Equal(t, []byte(v2), b.Bytes()) {
		return
	}

}

func TestBuffer_Base64Encode(t *testing.T) {
	b := Buffer{'a', 'b', 'c'}
	v, err := b.Base64Encode()
	if !assert.NoError(t, err, "Base64 encode is successful") {
		return
	}
	if !assert.Equal(t, []byte{'Y', 'W', 'J', 'j'}, v) {
		return
	}
}

func TestJSON(t *testing.T) {
	b1 := Buffer{'a', 'b', 'c'}

	jsontxt, err := json.Marshal(b1)
	if !assert.NoError(t, err) {
		return
	}

	if !assert.Equal(t, `"YWJj"`, string(jsontxt)) {
		return
	}

	var b2 Buffer
	if !assert.NoError(t, json.Unmarshal(jsontxt, &b2)) {
		return
	}

	if !assert.Equal(t, b1, b2) {
		return
	}
}