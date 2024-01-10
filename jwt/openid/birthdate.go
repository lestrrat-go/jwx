package openid

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"

	"github.com/lestrrat-go/jwx/v2/internal/json"
)

// https://openid.net/specs/openid-connect-core-1_0.html
//
// End-User's birthday, represented as an ISO 8601:2004 [ISO8601‑2004] YYYY-MM-DD format.
// The year MAY be 0000, indicating that it is omitted. To represent only the year, YYYY
// format is allowed. Note that depending on the underlying platform's date related function,
// providing just year can result in varying month and day, so the implementers need to
// take this factor into account to correctly process the dates.

type BirthdateClaim struct {
	year  *int
	month *int
	day   *int
}

func (b BirthdateClaim) Year() int {
	if b.year == nil {
		return 0
	}
	return *(b.year)
}

func (b BirthdateClaim) Month() int {
	if b.month == nil {
		return 0
	}
	return *(b.month)
}

func (b BirthdateClaim) Day() int {
	if b.day == nil {
		return 0
	}
	return *(b.day)
}

func (b *BirthdateClaim) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf(`failed to unmarshal JSON string for birthdate claim: %w`, err)
	}

	if err := b.Accept(s); err != nil {
		return fmt.Errorf(`failed to accept JSON value for birthdate claim: %w`, err)
	}
	return nil
}

var intSize int

func init() {
	switch math.MaxInt {
	case math.MaxInt16:
		intSize = 16
	case math.MaxInt32:
		intSize = 32
	case math.MaxInt64:
		intSize = 64
	}
}

func parseBirthdayInt(s string) int {
	i, _ := strconv.ParseInt(s, 10, intSize)
	return int(i)
}

var birthdateRx = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})$`)

// Accepts a value read from JSON, and converts it to a BirthdateClaim.
// This method DOES NOT verify the correctness of a date.
// Consumers should check for validity of dates such as Apr 31 et al
func (b *BirthdateClaim) Accept(v interface{}) error {
	b.year = nil
	b.month = nil
	b.day = nil
	switch v := v.(type) {
	case *BirthdateClaim:
		if ptr := v.year; ptr != nil {
			year := *ptr
			b.year = &year
		}
		if ptr := v.month; ptr != nil {
			month := *ptr
			b.month = &month
		}
		if ptr := v.day; ptr != nil {
			day := *ptr
			b.day = &day
		}
		return nil
	case string:
		// yeah, regexp is slow. PR's welcome
		indices := birthdateRx.FindStringSubmatchIndex(v)
		if indices == nil {
			return fmt.Errorf(`invalid pattern for birthdate`)
		}
		var tmp BirthdateClaim

		// Okay, this really isn't kosher, but we're doing this for
		// the coverage game... Because birthdateRx already checked that
		// the string contains 3 strings with consecutive decimal values
		// we can assume that strconv.ParseInt always succeeds.
		// strconv.ParseInt (and strconv.ParseUint that it uses internally)
		// only returns range errors, so we should be safe.
		year := parseBirthdayInt(v[indices[2]:indices[3]])
		if year <= 0 {
			return fmt.Errorf(`failed to parse birthdate year`)
		}
		tmp.year = &year

		month := parseBirthdayInt(v[indices[4]:indices[5]])
		if month <= 0 {
			return fmt.Errorf(`failed to parse birthdate month`)
		}
		tmp.month = &month

		day := parseBirthdayInt(v[indices[6]:indices[7]])
		if day <= 0 {
			return fmt.Errorf(`failed to parse birthdate day`)
		}
		tmp.day = &day

		*b = tmp
		return nil
	default:
		return fmt.Errorf(`invalid type for birthdate: %T`, v)
	}
}

func (b BirthdateClaim) encode(dst io.Writer) {
	fmt.Fprintf(dst, "%04d-%02d-%02d", b.Year(), b.Month(), b.Day())
}

func (b BirthdateClaim) String() string {
	var buf bytes.Buffer
	b.encode(&buf)
	return buf.String()
}

func (b BirthdateClaim) MarshalText() ([]byte, error) {
	var buf bytes.Buffer
	b.encode(&buf)
	return buf.Bytes(), nil
}
