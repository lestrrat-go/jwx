package jwk

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCacheDuration(t *testing.T) {
	t.Parallel()
	//Mon, 02 Jan 2006 15:04:05 GMT

	minDuration := 15 * time.Second
	tests := []struct {
		name     string
		expected time.Duration
		headers  func() *http.Header
	}{
		{
			name:     "cache-control 1",
			expected: 30 * time.Second,
			headers: func() *http.Header {
				h := make(http.Header)
				h.Add("cache-control", "max-age=30, must-revalidate")
				return &h
			},
		},
		{
			name:     "cache-control 2",
			expected: 30 * time.Second,
			headers: func() *http.Header {
				h := make(http.Header)
				h.Add("cache-control", "must-revalidate, max-age=30 ")
				return &h
			},
		},
		{
			name:     "cache-control 3",
			expected: minDuration,
			headers: func() *http.Header {
				h := make(http.Header)
				h.Add("cache-control", "max-age=10")
				return &h
			},
		},
		{
			name:     "expires 1",
			expected: 30 * time.Second,
			headers: func() *http.Header {
				h := make(http.Header)
				ts := httpTime(30)
				t.Log(ts)
				h.Add("Expires", ts)
				return &h
			},
		},
		{
			name:     "expires 2",
			expected: 30 * time.Second,
			headers: func() *http.Header {
				h := make(http.Header)
				ts := httpTime(30)
				h.Add("Expires", ts)
				return &h
			},
		},
		{
			name:     "combo 1",
			expected: 30 * time.Second,
			headers: func() *http.Header {
				h := make(http.Header)
				ts := httpTime(60)
				h.Add("Expires", ts)
				h.Add("cache-control", "max-age=30, must-revalidate")
				return &h
			},
		},
		{
			name:     "combo 2",
			expected: 30 * time.Second,
			headers: func() *http.Header {
				h := make(http.Header)
				ts := httpTime(60)
				h.Add("Expires", ts)
				h.Add("cache-control", "must-revalidate")
				h.Add("cache-control", "s-maxage=99")
				h.Add("cache-control", " max-age=30 ")
				return &h
			},
		},
		{
			name:     "invalid 1",
			expected: minDuration,
			headers: func() *http.Header {
				h := make(http.Header)
				ts := httpTime(-60)
				h.Add("Expires", ts)
				h.Add("cache-control", "must-revalidate")
				h.Add("cache-control", "s-maxage=99")
				h.Add("cache-control", " max-age=-30 ")
				return &h
			},
		},
		{
			name:     "invalid 2",
			expected: minDuration,
			headers: func() *http.Header {
				h := make(http.Header)
				h.Add("Expires", "not a valid timestamp")
				return &h
			},
		},
		{
			name:     "invalid 3",
			expected: minDuration,
			headers: func() *http.Header {
				h := make(http.Header)
				h.Add("cache-control", "max-age=999999999999999999999")
				return &h
			},
		},
	}

	for _, tc := range tests {
		h := tc.headers()
		d := getCacheDuration(h, minDuration).Round(5 * time.Second)
		if !assert.Equal(t, tc.expected, d, `getCacheDuration should produce expected value for `+tc.name) {
			return
		}
	}
}

func httpTime(seconds int) string {
	return time.Now().UTC().Add(time.Duration(seconds) * time.Second).Format(http.TimeFormat)
}
