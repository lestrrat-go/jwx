package jwe_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v2/internal/json"

	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/stretchr/testify/assert"
)

func TestRecipient(t *testing.T) {
	t.Run("JSON Marshaling", func(t *testing.T) {
		const src = `{"header":{"foo":"bar"},"encrypted_key":"Zm9vYmFyYmF6"}`
		r1 := jwe.NewRecipient()

		if !assert.NoError(t, json.Unmarshal([]byte(src), r1), `json.Unmarshal should succeed`) {
			return
		}

		buf, err := json.Marshal(r1)
		if !assert.NoError(t, err, `json.Marshal should succeed`) {
			return
		}

		if !assert.Equal(t, []byte(src), buf, `json representation should match`) {
			return
		}
	})
}
