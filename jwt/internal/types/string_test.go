package types_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwt/internal/types"
	"github.com/stretchr/testify/require"
)

func TestStringList_Accept(t *testing.T) {
	t.Parallel()

	var x types.StringList
	interfaceList := make([]any, 0, 2)
	interfaceList = append(interfaceList, "first")
	interfaceList = append(interfaceList, "second")
	require.NoError(t, x.Accept(interfaceList), "failed to convert []any into StringList")
}
