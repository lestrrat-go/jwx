package types_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwt/internal/types"
	"github.com/stretchr/testify/assert"
)

func TestStringList_Accept(t *testing.T) {
	t.Parallel()

	var x types.StringList
	interfaceList := make([]interface{}, 0)
	interfaceList = append(interfaceList, "first")
	interfaceList = append(interfaceList, "second")
	if !assert.NoError(t, x.Accept(interfaceList), "failed to convert []interface{} into StringList") {
		return
	}
}
