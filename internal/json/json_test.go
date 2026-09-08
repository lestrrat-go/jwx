package json_test

import (
	"bytes"
	jsonv2 "encoding/json/v2"
	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/stretchr/testify/require"
)

func TestWriteQuotedKey(t *testing.T) {
	t.Parallel()

	// Every name here must come back out as exactly one member whose key
	// is byte-for-byte what went in, no matter what it contains.
	names := map[string]string{
		"plain":         "hello",
		"quote":         `hello"world`,
		"injection":     `x":0,"admin`,
		"backslash":     `a\b`,
		"newline":       "a\nb",
		"tab":           "a\tb",
		"nul":           "a\x00b",
		"del":           "a\x7fb",
		"unicode":       "日本語",
		"empty":         "",
		"closing brace": `a"}`,
	}

	for label, name := range names {
		t.Run(label, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			buf.WriteByte('{')
			require.NoError(t, json.WriteQuotedKey(&buf, name), `WriteQuotedKey should succeed`)
			buf.WriteString(`true`)
			buf.WriteByte('}')

			var got map[string]any
			require.NoError(t, jsonv2.Unmarshal(buf.Bytes(), &got), `output should be valid JSON: %s`, buf.String())
			require.Len(t, got, 1, `exactly one member should be produced: %s`, buf.String())
			require.Contains(t, got, name, `member name should round-trip unchanged: %s`, buf.String())
		})
	}
}

func TestWriteQuotedKeyInvalidUTF8(t *testing.T) {
	t.Parallel()

	// Invalid UTF-8 must not be silently emitted raw. Either it is escaped
	// into valid JSON or the call reports an error; both leave the object
	// structure intact.
	var buf bytes.Buffer
	buf.WriteByte('{')
	err := json.WriteQuotedKey(&buf, "a\xffb")
	if err != nil {
		return
	}
	buf.WriteString(`true`)
	buf.WriteByte('}')

	var got map[string]any
	require.NoError(t, jsonv2.Unmarshal(buf.Bytes(), &got), `output should be valid JSON: %q`, buf.String())
	require.Len(t, got, 1, `exactly one member should be produced: %q`, buf.String())
}
