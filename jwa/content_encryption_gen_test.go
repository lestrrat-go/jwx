// Code generated by tools/cmd/genjwa/main.go. DO NOT EDIT

package jwa_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/stretchr/testify/assert"
)

func TestContentEncryptionAlgorithm(t *testing.T) {
	t.Parallel()
	t.Run(`accept jwa constant A128CBC_HS256`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.ContentEncryptionAlgorithm
		if !assert.NoError(t, dst.Accept(jwa.A128CBC_HS256), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.A128CBC_HS256, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept the string A128CBC-HS256`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.ContentEncryptionAlgorithm
		if !assert.NoError(t, dst.Accept("A128CBC-HS256"), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.A128CBC_HS256, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept fmt.Stringer for A128CBC-HS256`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.ContentEncryptionAlgorithm
		if !assert.NoError(t, dst.Accept(stringer{src: "A128CBC-HS256"}), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.A128CBC_HS256, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`stringification for A128CBC-HS256`, func(t *testing.T) {
		t.Parallel()
		if !assert.Equal(t, "A128CBC-HS256", jwa.A128CBC_HS256.String(), `stringified value matches`) {
			return
		}
	})
	t.Run(`accept jwa constant A128GCM`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.ContentEncryptionAlgorithm
		if !assert.NoError(t, dst.Accept(jwa.A128GCM), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.A128GCM, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept the string A128GCM`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.ContentEncryptionAlgorithm
		if !assert.NoError(t, dst.Accept("A128GCM"), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.A128GCM, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept fmt.Stringer for A128GCM`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.ContentEncryptionAlgorithm
		if !assert.NoError(t, dst.Accept(stringer{src: "A128GCM"}), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.A128GCM, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`stringification for A128GCM`, func(t *testing.T) {
		t.Parallel()
		if !assert.Equal(t, "A128GCM", jwa.A128GCM.String(), `stringified value matches`) {
			return
		}
	})
	t.Run(`accept jwa constant A192CBC_HS384`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.ContentEncryptionAlgorithm
		if !assert.NoError(t, dst.Accept(jwa.A192CBC_HS384), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.A192CBC_HS384, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept the string A192CBC-HS384`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.ContentEncryptionAlgorithm
		if !assert.NoError(t, dst.Accept("A192CBC-HS384"), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.A192CBC_HS384, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept fmt.Stringer for A192CBC-HS384`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.ContentEncryptionAlgorithm
		if !assert.NoError(t, dst.Accept(stringer{src: "A192CBC-HS384"}), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.A192CBC_HS384, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`stringification for A192CBC-HS384`, func(t *testing.T) {
		t.Parallel()
		if !assert.Equal(t, "A192CBC-HS384", jwa.A192CBC_HS384.String(), `stringified value matches`) {
			return
		}
	})
	t.Run(`accept jwa constant A192GCM`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.ContentEncryptionAlgorithm
		if !assert.NoError(t, dst.Accept(jwa.A192GCM), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.A192GCM, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept the string A192GCM`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.ContentEncryptionAlgorithm
		if !assert.NoError(t, dst.Accept("A192GCM"), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.A192GCM, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept fmt.Stringer for A192GCM`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.ContentEncryptionAlgorithm
		if !assert.NoError(t, dst.Accept(stringer{src: "A192GCM"}), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.A192GCM, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`stringification for A192GCM`, func(t *testing.T) {
		t.Parallel()
		if !assert.Equal(t, "A192GCM", jwa.A192GCM.String(), `stringified value matches`) {
			return
		}
	})
	t.Run(`accept jwa constant A256CBC_HS512`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.ContentEncryptionAlgorithm
		if !assert.NoError(t, dst.Accept(jwa.A256CBC_HS512), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.A256CBC_HS512, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept the string A256CBC-HS512`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.ContentEncryptionAlgorithm
		if !assert.NoError(t, dst.Accept("A256CBC-HS512"), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.A256CBC_HS512, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept fmt.Stringer for A256CBC-HS512`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.ContentEncryptionAlgorithm
		if !assert.NoError(t, dst.Accept(stringer{src: "A256CBC-HS512"}), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.A256CBC_HS512, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`stringification for A256CBC-HS512`, func(t *testing.T) {
		t.Parallel()
		if !assert.Equal(t, "A256CBC-HS512", jwa.A256CBC_HS512.String(), `stringified value matches`) {
			return
		}
	})
	t.Run(`accept jwa constant A256GCM`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.ContentEncryptionAlgorithm
		if !assert.NoError(t, dst.Accept(jwa.A256GCM), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.A256GCM, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept the string A256GCM`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.ContentEncryptionAlgorithm
		if !assert.NoError(t, dst.Accept("A256GCM"), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.A256GCM, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept fmt.Stringer for A256GCM`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.ContentEncryptionAlgorithm
		if !assert.NoError(t, dst.Accept(stringer{src: "A256GCM"}), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.A256GCM, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`stringification for A256GCM`, func(t *testing.T) {
		t.Parallel()
		if !assert.Equal(t, "A256GCM", jwa.A256GCM.String(), `stringified value matches`) {
			return
		}
	})
	t.Run(`bail out on random integer value`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.ContentEncryptionAlgorithm
		if !assert.Error(t, dst.Accept(1), `accept should fail`) {
			return
		}
	})
	t.Run(`do not accept invalid (totally made up) string value`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.ContentEncryptionAlgorithm
		if !assert.Error(t, dst.Accept(`totallyInvalidValue`), `accept should fail`) {
			return
		}
	})
	t.Run(`check list of elements`, func(t *testing.T) {
		t.Parallel()
		var expected = map[jwa.ContentEncryptionAlgorithm]struct{}{
			jwa.A128CBC_HS256: {},
			jwa.A128GCM:       {},
			jwa.A192CBC_HS384: {},
			jwa.A192GCM:       {},
			jwa.A256CBC_HS512: {},
			jwa.A256GCM:       {},
		}
		for _, v := range jwa.ContentEncryptionAlgorithms() {
			if _, ok := expected[v]; !assert.True(t, ok, `%s should be in the expected list`, v) {
				return
			}
			delete(expected, v)
		}
		if !assert.Len(t, expected, 0) {
			return
		}
	})
}

// Note: this test can NOT be run in parallel as it uses options with global effect.
func TestContentEncryptionAlgorithmCustomAlgorithm(t *testing.T) {
	// These subtests can NOT be run in parallel as options with global effect change.
	customAlgorithm := jwa.ContentEncryptionAlgorithm("custom-algorithm")
	// Unregister the custom algorithm, in case tests fail.
	t.Cleanup(func() {
		jwa.UnregisterContentEncryptionAlgorithm(customAlgorithm)
	})
	t.Run(`with custom algorithm registered`, func(t *testing.T) {
		jwa.RegisterContentEncryptionAlgorithm(customAlgorithm)
		t.Run(`accept variable used to register custom algorithm`, func(t *testing.T) {
			t.Parallel()
			var dst jwa.ContentEncryptionAlgorithm
			if !assert.NoError(t, dst.Accept(customAlgorithm), `accept is successful`) {
				return
			}
			assert.Equal(t, customAlgorithm, dst, `accepted value should be equal to variable`)
		})
		t.Run(`accept the string custom-algorithm`, func(t *testing.T) {
			t.Parallel()
			var dst jwa.ContentEncryptionAlgorithm
			if !assert.NoError(t, dst.Accept(`custom-algorithm`), `accept is successful`) {
				return
			}
			assert.Equal(t, customAlgorithm, dst, `accepted value should be equal to variable`)
		})
		t.Run(`accept fmt.Stringer for custom-algorithm`, func(t *testing.T) {
			t.Parallel()
			var dst jwa.ContentEncryptionAlgorithm
			if !assert.NoError(t, dst.Accept(stringer{src: `custom-algorithm`}), `accept is successful`) {
				return
			}
			assert.Equal(t, customAlgorithm, dst, `accepted value should be equal to variable`)
		})
	})
	t.Run(`with custom algorithm deregistered`, func(t *testing.T) {
		jwa.UnregisterContentEncryptionAlgorithm(customAlgorithm)
		t.Run(`reject variable used to register custom algorithm`, func(t *testing.T) {
			t.Parallel()
			var dst jwa.ContentEncryptionAlgorithm
			assert.Error(t, dst.Accept(customAlgorithm), `accept failed`)
		})
		t.Run(`reject the string custom-algorithm`, func(t *testing.T) {
			t.Parallel()
			var dst jwa.ContentEncryptionAlgorithm
			assert.Error(t, dst.Accept(`custom-algorithm`), `accept failed`)
		})
		t.Run(`reject fmt.Stringer for custom-algorithm`, func(t *testing.T) {
			t.Parallel()
			var dst jwa.ContentEncryptionAlgorithm
			assert.Error(t, dst.Accept(stringer{src: `custom-algorithm`}), `accept failed`)
		})
	})
}
