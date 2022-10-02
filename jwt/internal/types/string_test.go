package types_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwt/internal/types"
	"github.com/stretchr/testify/assert"
)

func TestAudience_AcceptValue(t *testing.T) {
	t.Parallel()

	var x types.Audience
	interfaceList := make([]interface{}, 0)
	interfaceList = append(interfaceList, "first")
	interfaceList = append(interfaceList, "second")
	if !assert.NoError(t, x.AcceptValue(interfaceList), "failed to convert []interface{} into StringList") {
		return
	}
}
