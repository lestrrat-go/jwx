package jwt

import (
	"time"
)

type stringList []string

// NumericDate represents the date format used in the 'nbf' claim
type NumericDate struct {
	time.Time
}
