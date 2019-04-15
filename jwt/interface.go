package jwt

import (
	"time"
)

type StringList []string

// NumericDate represents the date format used in the 'nbf' claim
type NumericDate struct {
	time.Time
}
