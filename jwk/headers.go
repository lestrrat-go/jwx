package jwk

import (
	"reflect"

	"github.com/pkg/errors"
)

/*
func (h *stdHeaders) Iterate(ctx context.Context) HeaderIterator {
	ch := make(chan *HeaderPair)
	go h.iterate(ctx, ch)
	return mapiter.New(ch)
}

func (h *stdHeaders) Walk(ctx context.Context, visitor HeaderVisitor) error {
	return iter.WalkMap(ctx, h, visitor)
}

func (h *stdHeaders) AsMap(ctx context.Context) (map[string]interface{}, error) {
	return iter.AsMap(ctx, h)
}

*/

func getRequiredKey(h Headers, s string) ([]byte, error) {
	return getKey(h, s, true)
}

func getOptionalKey(h Headers, s string) ([]byte, error) {
	return getKey(h, s, false)
}

func getKey(h Headers, s string, required bool) ([]byte, error) {
	v, ok := h.Get(s)
	if !ok {
		if required {
			return nil, errors.Errorf(`required key %#v was not found`, s)
		}
		return nil, errors.Errorf(`key %#v was not found`, s)
	}

	switch v := v.(type) {
	case string:
		return []byte(v), nil
	case []byte:
		return v, nil
		/*
			switch v := v.(type) {
			case string:
				buf, err := base64.DecodeString(v)
				if err != nil {
					return nil, errors.Wrapf(err, `failed to base64 decode key %#v: %#v`, s, v)
				}
				return buf, nil
			case []byte:
				return v, nil
		*/
	default:
		return nil, errors.Errorf(`invalid type for key %#v: %T`, s, v)
	}
}

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
