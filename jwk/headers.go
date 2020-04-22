package jwk

import (
	"reflect"

	"github.com/pkg/errors"
)

func assignMaterializeResult(v, t interface{}) error {
	result := reflect.ValueOf(t)

	// t can be a pointer or a slice, and the code will slightly change
	// depending on this
	var isSlice bool
	switch result.Kind() {
	case reflect.Ptr:
		// no op
	case reflect.Slice:
		isSlice = true
	default:
		return errors.Errorf("argument t to assignMaterializeResult must be a pointer or a slice: %T", t)
	}

	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Ptr {
		return errors.Errorf(`argument to Materialize() must be a pointer: %T`, v)
	}

	dst := rv.Elem()
	switch dst.Kind() {
	case reflect.Interface:
		// If it's an interface, we can just assign the pointer to the interface{}
	default:
		// If it's a pointer to the struct we're looking for, we need to set
		// the de-referenced struct
		if !isSlice {
			result = result.Elem()
		}
	}
	if !result.Type().AssignableTo(dst.Type()) {
		return errors.Errorf(`argument to Materialize() must be compatible with %T (was %T)`, result.Interface(), t)
	}

	if !dst.CanSet() {
		return errors.Errorf(`argument to Materialize() must be settable`)
	}
	dst.Set(result)

	return nil
}
