package types_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwt/internal/types"
	"github.com/stretchr/testify/require"
)

func TestStringList_Accept(t *testing.T) {
	t.Parallel()

	var x types.StringList
	interfaceList := make([]interface{}, 0)
	interfaceList = append(interfaceList, "first")
	interfaceList = append(interfaceList, "second")
	require.NoError(t, x.Accept(interfaceList), "failed to convert []interface{} into StringList")
}
