// this file was auto-generated by internal/cmd/gentypes/main.go: DO NOT EDIT

package jwa_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/stretchr/testify/assert"
)

func TestSignatureAlgorithm(t *testing.T) {
	t.Parallel()
	t.Run(`accept jwa constant ES256`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept(jwa.ES256), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.ES256, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept the string ES256`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept("ES256"), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.ES256, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept fmt.Stringer for ES256`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept(stringer{src: "ES256"}), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.ES256, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`stringification for ES256`, func(t *testing.T) {
		t.Parallel()
		if !assert.Equal(t, "ES256", jwa.ES256.String(), `stringified value matches`) {
			return
		}
	})
	t.Run(`accept jwa constant ES256K`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept(jwa.ES256K), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.ES256K, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept the string ES256K`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept("ES256K"), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.ES256K, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept fmt.Stringer for ES256K`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept(stringer{src: "ES256K"}), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.ES256K, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`stringification for ES256K`, func(t *testing.T) {
		t.Parallel()
		if !assert.Equal(t, "ES256K", jwa.ES256K.String(), `stringified value matches`) {
			return
		}
	})
	t.Run(`accept jwa constant ES384`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept(jwa.ES384), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.ES384, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept the string ES384`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept("ES384"), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.ES384, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept fmt.Stringer for ES384`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept(stringer{src: "ES384"}), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.ES384, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`stringification for ES384`, func(t *testing.T) {
		t.Parallel()
		if !assert.Equal(t, "ES384", jwa.ES384.String(), `stringified value matches`) {
			return
		}
	})
	t.Run(`accept jwa constant ES512`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept(jwa.ES512), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.ES512, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept the string ES512`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept("ES512"), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.ES512, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept fmt.Stringer for ES512`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept(stringer{src: "ES512"}), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.ES512, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`stringification for ES512`, func(t *testing.T) {
		t.Parallel()
		if !assert.Equal(t, "ES512", jwa.ES512.String(), `stringified value matches`) {
			return
		}
	})
	t.Run(`accept jwa constant EdDSA`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept(jwa.EdDSA), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.EdDSA, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept the string EdDSA`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept("EdDSA"), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.EdDSA, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept fmt.Stringer for EdDSA`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept(stringer{src: "EdDSA"}), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.EdDSA, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`stringification for EdDSA`, func(t *testing.T) {
		t.Parallel()
		if !assert.Equal(t, "EdDSA", jwa.EdDSA.String(), `stringified value matches`) {
			return
		}
	})
	t.Run(`accept jwa constant HS256`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept(jwa.HS256), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.HS256, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept the string HS256`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept("HS256"), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.HS256, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept fmt.Stringer for HS256`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept(stringer{src: "HS256"}), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.HS256, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`stringification for HS256`, func(t *testing.T) {
		t.Parallel()
		if !assert.Equal(t, "HS256", jwa.HS256.String(), `stringified value matches`) {
			return
		}
	})
	t.Run(`accept jwa constant HS384`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept(jwa.HS384), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.HS384, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept the string HS384`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept("HS384"), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.HS384, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept fmt.Stringer for HS384`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept(stringer{src: "HS384"}), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.HS384, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`stringification for HS384`, func(t *testing.T) {
		t.Parallel()
		if !assert.Equal(t, "HS384", jwa.HS384.String(), `stringified value matches`) {
			return
		}
	})
	t.Run(`accept jwa constant HS512`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept(jwa.HS512), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.HS512, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept the string HS512`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept("HS512"), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.HS512, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept fmt.Stringer for HS512`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept(stringer{src: "HS512"}), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.HS512, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`stringification for HS512`, func(t *testing.T) {
		t.Parallel()
		if !assert.Equal(t, "HS512", jwa.HS512.String(), `stringified value matches`) {
			return
		}
	})
	t.Run(`accept jwa constant NoSignature`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept(jwa.NoSignature), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.NoSignature, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept the string none`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept("none"), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.NoSignature, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept fmt.Stringer for none`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept(stringer{src: "none"}), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.NoSignature, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`stringification for none`, func(t *testing.T) {
		t.Parallel()
		if !assert.Equal(t, "none", jwa.NoSignature.String(), `stringified value matches`) {
			return
		}
	})
	t.Run(`accept jwa constant PS256`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept(jwa.PS256), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.PS256, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept the string PS256`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept("PS256"), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.PS256, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept fmt.Stringer for PS256`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept(stringer{src: "PS256"}), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.PS256, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`stringification for PS256`, func(t *testing.T) {
		t.Parallel()
		if !assert.Equal(t, "PS256", jwa.PS256.String(), `stringified value matches`) {
			return
		}
	})
	t.Run(`accept jwa constant PS384`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept(jwa.PS384), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.PS384, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept the string PS384`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept("PS384"), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.PS384, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept fmt.Stringer for PS384`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept(stringer{src: "PS384"}), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.PS384, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`stringification for PS384`, func(t *testing.T) {
		t.Parallel()
		if !assert.Equal(t, "PS384", jwa.PS384.String(), `stringified value matches`) {
			return
		}
	})
	t.Run(`accept jwa constant PS512`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept(jwa.PS512), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.PS512, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept the string PS512`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept("PS512"), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.PS512, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept fmt.Stringer for PS512`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept(stringer{src: "PS512"}), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.PS512, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`stringification for PS512`, func(t *testing.T) {
		t.Parallel()
		if !assert.Equal(t, "PS512", jwa.PS512.String(), `stringified value matches`) {
			return
		}
	})
	t.Run(`accept jwa constant RS256`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept(jwa.RS256), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.RS256, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept the string RS256`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept("RS256"), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.RS256, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept fmt.Stringer for RS256`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept(stringer{src: "RS256"}), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.RS256, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`stringification for RS256`, func(t *testing.T) {
		t.Parallel()
		if !assert.Equal(t, "RS256", jwa.RS256.String(), `stringified value matches`) {
			return
		}
	})
	t.Run(`accept jwa constant RS384`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept(jwa.RS384), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.RS384, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept the string RS384`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept("RS384"), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.RS384, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept fmt.Stringer for RS384`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept(stringer{src: "RS384"}), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.RS384, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`stringification for RS384`, func(t *testing.T) {
		t.Parallel()
		if !assert.Equal(t, "RS384", jwa.RS384.String(), `stringified value matches`) {
			return
		}
	})
	t.Run(`accept jwa constant RS512`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept(jwa.RS512), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.RS512, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept the string RS512`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept("RS512"), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.RS512, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`accept fmt.Stringer for RS512`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.NoError(t, dst.Accept(stringer{src: "RS512"}), `accept is successful`) {
			return
		}
		if !assert.Equal(t, jwa.RS512, dst, `accepted value should be equal to constant`) {
			return
		}
	})
	t.Run(`stringification for RS512`, func(t *testing.T) {
		t.Parallel()
		if !assert.Equal(t, "RS512", jwa.RS512.String(), `stringified value matches`) {
			return
		}
	})
	t.Run(`bail out on random integer value`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.Error(t, dst.Accept(1), `accept should fail`) {
			return
		}
	})
	t.Run(`do not accept invalid (totally made up) string value`, func(t *testing.T) {
		t.Parallel()
		var dst jwa.SignatureAlgorithm
		if !assert.Error(t, dst.Accept(`totallyInvfalidValue`), `accept should fail`) {
			return
		}
	})
	t.Run(`check list of elements`, func(t *testing.T) {
		t.Parallel()
		var expected = map[jwa.SignatureAlgorithm]struct{}{
			jwa.ES256:       {},
			jwa.ES256K:      {},
			jwa.ES384:       {},
			jwa.ES512:       {},
			jwa.EdDSA:       {},
			jwa.HS256:       {},
			jwa.HS384:       {},
			jwa.HS512:       {},
			jwa.NoSignature: {},
			jwa.PS256:       {},
			jwa.PS384:       {},
			jwa.PS512:       {},
			jwa.RS256:       {},
			jwa.RS384:       {},
			jwa.RS512:       {},
		}
		for _, v := range jwa.SignatureAlgorithms() {
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
