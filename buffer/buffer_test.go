package buffer

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuffer_Base64Encode(t *testing.T) {
	b := Buffer{'a', 'b', 'c'}
	v, err := b.Base64Encode()
	if assert.NoError(t, err, "Base64 encode is successful") {
		return
	}
	assert.Equal(t, []byte{'Y', 'W', 'J', 'j'}, v)
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

	assert.Equal(t, b1, b2)
}