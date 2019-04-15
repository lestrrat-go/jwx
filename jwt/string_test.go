package jwt_test

import (
	"github.com/lestrrat-go/jwx/jwt"
	"testing"
)

func TestStringList_Accept(t *testing.T) {

	var x jwt.StringList
	interfaceList := make([]interface{}, 0)
	interfaceList = append(interfaceList, "first")
	interfaceList = append(interfaceList, "second")
	err := x.Accept(interfaceList)
	if err != nil {
		t.Fatal("Failed to convert []interface{} into StringList: %", err.Error())
	}
}
