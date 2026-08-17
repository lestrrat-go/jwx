//go:build go1.27

package json

import (
	"errors"
)

// errSkipFunc is the sentinel a marshal/unmarshal function returns to decline
// handling a value, so that the next applicable function (or the default
// behavior) is used instead.
//
// Go 1.27 removed json/v2.SkipFunc and gave the role to errors.ErrUnsupported,
// which json/v2 now matches with errors.Is rather than by identity.
var errSkipFunc = errors.ErrUnsupported
