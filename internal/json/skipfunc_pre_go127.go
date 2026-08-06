//go:build !go1.27

package json

import (
	jsonv2 "encoding/json/v2"
)

// errSkipFunc is the sentinel a marshal/unmarshal function returns to decline
// handling a value, so that the next applicable function (or the default
// behavior) is used instead.
//
// Go 1.26 spells it json/v2.SkipFunc and compares it by identity
// (`err == SkipFunc`), so it has to be returned verbatim.
var errSkipFunc = jsonv2.SkipFunc
