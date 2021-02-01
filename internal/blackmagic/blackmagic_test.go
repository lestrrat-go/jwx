package blackmagic_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/internal/blackmagic"
	"github.com/stretchr/testify/assert"
)

func TestAssignment(t *testing.T) {
	testcases := []struct {
		Name        string
		Error       bool
		Value       interface{}
		Destination func() interface{}
	}{
		{
			Name:  `empty struct`,
			Error: true,
			Value: struct{}{},
			Destination: func() interface{} {
				var v interface{}
				return &v
			},
		},
		{
			Name:  `non pointer destination`,
			Error: true,
			Value: &struct{}{},
		},
		{
			Name:  `assign empty struct to int`,
			Error: true,
			Value: &struct{}{},
			Destination: func() interface{} {
				var v int
				return &v
			},
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			var dst interface{}
			if dstFunc := tc.Destination; dstFunc != nil {
				dst = dstFunc()
			}
			err := blackmagic.AssignIfCompatible(dst, tc.Value)
			if tc.Error {
				if !assert.Error(t, err, `blackmagic.AssignIfCompatible should fail`) {
					return
				}
			} else {
				if !assert.NoError(t, err, `blackmagic.AssignIfCompatible should succeed`) {
					return
				}
			}
		})
	}
}
