package types

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/internal/json"
)

const (
	DefaultPrecision uint32 = 0 // second level
	MaxPrecision     uint32 = 9 // nanosecond level
)

var ParsePrecision = DefaultPrecision
var FormatPrecision = DefaultPrecision

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

func intToTime(v interface{}, t *time.Time) bool {
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
	var t time.Time
	var fractional string
	var whole string = x
	if i := strings.IndexRune(x, '.'); i > 0 {
		if ParsePrecision == 0 {
			fractional = ""
		} else {
			fractional = x[i:]
		}

		if int(ParsePrecision) < len(fractional)-1 {
			fractional = fractional[:int(ParsePrecision)+1]
		}
		whole = x[:i]
	}
	n, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return t, fmt.Errorf(`failed to parse alue %#v: %w`, x, err)
	}
	t = time.Unix(n, 0).UTC()
	if fractional != "" {
		s2 := strings.TrimSuffix(t.Format(time.RFC3339), `Z`) + fractional + `Z`
		t2, err := time.Parse(time.RFC3339, s2)
		if err != nil {
			return t, fmt.Errorf(`failed to convert json value %q to time.Time: %w`, x, err)
		}
		t = t2
	}
	return t, nil
}

func (n *NumericDate) Accept(v interface{}) error {
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
	case json.Number:
		tv, err := parseNumericString(x.String())
		if err != nil {
			return fmt.Errorf(`failed to accept json.Number %q: %w`, x.String(), err)
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
	n.Time = t.UTC()
	return nil
}

func (n NumericDate) String() string {
	if FormatPrecision == 0 {
		return strconv.FormatInt(n.Unix(), 10)
	}

	// This is cheating,but it's better (easier) than doing floating point math
	// We basically munge with strings after formatting an integer balue
	// for nanoseconds since epoch
	s := strconv.FormatInt(n.UnixNano(), 10)
	for len(s) < int(MaxPrecision) {
		s = "0" + s
	}

	slwhole := len(s) - int(MaxPrecision)
	s = s[:slwhole] + "." + s[slwhole:slwhole+int(FormatPrecision)]
	if s[0] == '.' {
		s = "0" + s
	}

	return s
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
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return fmt.Errorf(`failed to unmarshal date: %w`, err)
	}

	var n2 NumericDate
	if err := n2.Accept(v); err != nil {
		return fmt.Errorf(`invalid value for NumericDate: %w`, err)
	}
	*n = n2
	return nil
}
