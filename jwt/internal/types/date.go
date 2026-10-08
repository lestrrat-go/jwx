package types

import (
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/lestrrat-go/jwx/v4/internal/tokens"
)

const (
	DefaultPrecision uint32 = 0 // second level
	MaxPrecision     uint32 = 9 // nanosecond level
)

var Pedantic atomic.Uint32
var ParsePrecision atomic.Uint32
var FormatPrecision atomic.Uint32

// NumericDate represents the date format used in the 'nbf' claim
type NumericDate struct {
	time.Time
}

func (n *NumericDate) Get() time.Time {
	if n == nil {
		return (time.Time{}).UTC()
	}
	return n.Time
}

// validateNumericDateTime checks that Unix seconds and time.Time agree about
// whether a date is before January 1, 1970 UTC. Negative seconds must be
// before that instant; zero or positive seconds must be on or after it.
// time.Unix(math.MaxInt64, 0) breaks this rule: adding Go's internal time
// offset overflows, so Unix() stays positive while comparisons put the date
// before 1970.
func validateNumericDateTime(t time.Time) error {
	seconds := t.Unix()
	if (seconds < 0) != t.Before(time.Unix(0, 0)) {
		return fmt.Errorf(`NumericDate %d is out of range for time.Time`, seconds)
	}
	return nil
}

func intToTime(v any, t *time.Time) bool {
	var n int64
	switch x := v.(type) {
	case int64:
		n = x
	case int32:
		n = int64(x)
	case int16:
		n = int64(x)
	case int8:
		n = int64(x)
	case int:
		n = int64(x)
	default:
		return false
	}

	*t = time.Unix(n, 0)
	return true
}

func parseNumericString(x string) (time.Time, error) {
	var t time.Time // empty time for empty return value

	// Only check for the escape hatch if it's the pedantic
	// flag is off
	if Pedantic.Load() != 1 {
		// This is an escape hatch for non-conformant providers
		// that gives us RFC3339 instead of epoch time
		for _, r := range x {
			// 0x30 = '0', 0x39 = '9', 0x2E = tokens.Period
			if (r >= 0x30 && r <= 0x39) || r == 0x2E {
				continue
			}

			// if it got here, then it probably isn't epoch time
			tv, err := time.Parse(time.RFC3339, x)
			if err != nil {
				return t, fmt.Errorf(`value is not number of seconds since the epoch, and attempt to parse it as RFC3339 timestamp failed: %w`, err)
			}
			return tv, nil
		}
	}

	var fractional string
	whole := x
	parsePrecision := ParsePrecision.Load()
	if i := strings.IndexRune(x, tokens.Period); i > 0 {
		if parsePrecision > 0 && len(x) > i+1 {
			fractional = x[i+1:] // everything after the tokens.Period
			if int(parsePrecision) < len(fractional) {
				// Remove insignificant digits
				fractional = fractional[:int(parsePrecision)]
			}
			// Replace missing fractional diits with zeros
			for len(fractional) < int(MaxPrecision) {
				fractional = fractional + "0"
			}
		}
		whole = x[:i]
	}
	n, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return t, fmt.Errorf(`failed to parse whole value %q: %w`, whole, err)
	}
	var nsecs int64
	if fractional != "" {
		v, err := strconv.ParseInt(fractional, 10, 64)
		if err != nil {
			return t, fmt.Errorf(`failed to parse fractional value %q: %w`, fractional, err)
		}
		nsecs = v
	}

	return time.Unix(n, nsecs).UTC(), nil
}

func (n *NumericDate) Accept(v any) error {
	var t time.Time
	switch x := v.(type) {
	case float32:
		tv, err := parseNumericString(fmt.Sprintf(`%.9f`, x))
		if err != nil {
			return fmt.Errorf(`failed to accept float32 %.9f: %w`, x, err)
		}
		t = tv
	case float64:
		tv, err := parseNumericString(fmt.Sprintf(`%.9f`, x))
		if err != nil {
			return fmt.Errorf(`failed to accept float32 %.9f: %w`, x, err)
		}
		t = tv
	case string:
		tv, err := parseNumericString(x)
		if err != nil {
			return fmt.Errorf(`failed to accept string %q: %w`, x, err)
		}
		t = tv
	case time.Time:
		t = x
	default:
		if !intToTime(v, &t) {
			return fmt.Errorf(`invalid type %T`, v)
		}
	}
	if err := validateNumericDateTime(t); err != nil {
		return err
	}
	n.Time = t.UTC()
	return nil
}

func (n NumericDate) String() string {
	formatPrecision := FormatPrecision.Load()
	if formatPrecision == 0 {
		return strconv.FormatInt(n.Unix(), 10)
	}

	// Work from seconds and nanoseconds separately: UnixNano() only covers
	// the years 1678 through 2262, while a NumericDate can be any time.Time
	// that passes validateNumericDateTime.
	//
	// Unix() floors, so the nanoseconds are always added to the seconds,
	// even before 1970. The fraction is floored to the requested digits
	// too, which keeps precision N consistent with precision 0.
	sec := n.Unix()
	scale := int64(1)
	for range formatPrecision {
		scale *= 10
	}
	frac := int64(n.Nanosecond()) / (int64(time.Second) / scale)

	var buf [32]byte
	b := buf[:0]
	if sec < 0 && frac > 0 {
		// sec + frac/scale is a negative number whose whole part is
		// -(sec+1) and whose fraction is scale-frac. For example,
		// sec=-2 and frac=5 at precision 1 is written as "-1.5".
		b = append(b, '-')
		b = strconv.AppendInt(b, -(sec + 1), 10)
		frac = scale - frac
	} else {
		b = strconv.AppendInt(b, sec, 10)
	}
	b = append(b, tokens.Period)

	// Write exactly formatPrecision digits, keeping leading zeros
	var digits [MaxPrecision]byte
	for i := int(formatPrecision) - 1; i >= 0; i-- {
		digits[i] = byte('0' + frac%10)
		frac /= 10
	}
	b = append(b, digits[:formatPrecision]...)
	return string(b)
}

// MarshalJSON translates from internal representation to JSON NumericDate
// See https://tools.ietf.org/html/rfc7519#page-6
func (n *NumericDate) MarshalJSON() ([]byte, error) {
	if n.IsZero() {
		return json.Marshal(nil)
	}

	return json.Marshal(n.String())
}

func (n *NumericDate) UnmarshalJSON(data []byte) error {
	// Fast path: integer timestamps are the overwhelmingly common case in JWTs.
	// Parse them directly without going through json.Unmarshal → any → float64 → fmt.Sprintf → parseNumericString.
	if len(data) > 0 && data[0] >= '0' && data[0] <= '9' {
		// Check if it's a pure integer (no decimal point, no 'e' notation)
		isInt := true
		for _, b := range data {
			if b < '0' || b > '9' {
				isInt = false
				break
			}
		}
		if isInt {
			v, err := strconv.ParseInt(string(data), 10, 64)
			if err == nil {
				t := time.Unix(v, 0).UTC()
				if err := validateNumericDateTime(t); err != nil {
					return err
				}
				n.Time = t
				return nil
			}
		}
	}

	// Slow path: handles floats, strings, negative numbers, etc.
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return fmt.Errorf(`failed to unmarshal date: %w`, err)
	}
	if Pedantic.Load() == 1 {
		if _, ok := v.(float64); !ok {
			return fmt.Errorf(`invalid JSON type for NumericDate: expected a number, got %T`, v)
		}
	}

	var n2 NumericDate
	if err := n2.Accept(v); err != nil {
		return fmt.Errorf(`invalid value for NumericDate: %w`, err)
	}
	*n = n2
	return nil
}
